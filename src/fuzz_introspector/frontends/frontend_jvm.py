# Copyright 2024 Fuzz Introspector Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################
"""Fuzz Introspector Light frontend for Java"""

from typing import Optional

import os
import pathlib
import logging

from tree_sitter import Language, Parser, Node
import tree_sitter_java
import yaml

logger = logging.getLogger(name=__name__)
LOG_FMT = '%(asctime)s.%(msecs)03d %(levelname)s %(module)s - %(funcName)s: %(message)s'


class SourceCodeFile():
    """Class for holding file-specific information."""

    def __init__(self,
                 source_file: str,
                 entrypoint: str,
                 source_content: Optional[bytes] = None):
        logger.info('Processing %s' % source_file)

        self.root = None
        self.source_file = source_file
        self.entrypoint = entrypoint
        self.tree_sitter_lang = Language(tree_sitter_java.language())
        self.parser = Parser(self.tree_sitter_lang)

        if source_content:
            self.source_content = source_content
        else:
            with open(self.source_file, 'rb') as f:
                self.source_content = f.read()

        # List of definitions in the source file.
        self.package = ''
        self.classes = []
        self.imports = {}

        # Initialization ruotines
        self.load_tree()

        # Load package declaration
        self._set_package_declaration()

        # Load classes/interfaces delcaration
        self._set_class_interface_declaration()

        # Load import statements
        self._set_import_declaration()

    def load_tree(self):
        """Load the the source code into a treesitter tree, and set
        the root node."""
        self.root = self.parser.parse(self.source_content).root_node

    def _set_package_declaration(self):
        """Internal helper for retrieving the source package."""
        query = self.tree_sitter_lang.query('( package_declaration ) @fd ')
        res = query.captures(self.root)
        for _, nodes in res.items():
            for node in nodes:
                for package in node.children:
                    if package.type == 'scoped_identifier':
                        self.package = package.text.decode()

    def _set_class_interface_declaration(self):
        """Internal helper for retrieving all classes."""
        for node in self.root.children:
            if node.type == 'class_declaration' or node.type == 'interface_declaration':
                self.classes.append(
                    JavaClassInterface(node, self.tree_sitter_lang, self))

    def _set_import_declaration(self):
        """Internal helper for retrieving all import."""
        # Process by import statements
        query = self.tree_sitter_lang.query('( import_declaration ) @fd ')
        res = query.captures(self.root)
        for _, nodes in res.items():
            for node in nodes:
                package = ''
                wildcard = False
                for imp in node.children:
                    if imp.type == 'scoped_identifier':
                        package = imp.text.decode()
                    if imp.type == 'asterisk':
                        wildcard = True
                if not wildcard and not package.startswith('java.lang'):
                    self.imports[package.rsplit('.', 1)[-1]] = package

        # Process by classes/interfaces
        for cls in self.classes:
            name = cls.name
            if name.rsplit('.', 1)[-1] not in self.imports:
                self.imports[name.rsplit('.', 1)[-1]] = name

    def get_all_methods(self) -> dict[str, 'JavaMethod']:
        """Gets all JavaMethod object of all classes in this source file,
        mapped by its method name"""
        methods = {}
        for cls in self.classes:
            for method in cls.get_all_methods():
                methods[method.name] = method

        return methods

    def get_function_node(self, target_name: str) -> Optional['JavaMethod']:
        """Gets the tree-sitter node corresponding to a method."""
        methods = self.get_all_methods()
        return methods.get(target_name, None)

    def has_libfuzzer_harness(self) -> bool:
        """Returns whether the source code holds a libfuzzer harness"""
        if any(cls.has_libfuzzer_harness() for cls in self.classes):
            return True

        return False

    def has_function_definition(self, target_name: str) -> bool:
        """Returns if the source file holds a given function definition."""
        if any(
                cls.has_function_definition(target_name)
                for cls in self.classes):
            return True

        return False

    def get_entry_function_name(self) -> Optional[str]:
        """Returns the entry function name of the harness if found,"""
        return self.entrypoint


class Project():
    """Wrapper for doing analysis of a collection of source files."""

    def __init__(self, source_code_files: list[str]):
        self.source_code_files = source_code_files

    def dump_module_logic(self, report_name: str, entry_method: str = ''):
        """Dumps the data for the module in full."""
        logger.info('Dumping project-wide logic.')
        report = {'report': 'name'}
        report['sources'] = []

        # Log entry method if provided
        if entry_method:
            report['Fuzzing method'] = entry_method

        # Find all methods
        method_list = []
        for source_code in self.source_code_files:
            methods = source_code.get_all_methods()
            report['sources'].append({
                'source_file': source_code.source_file,
                'function_names': list(methods.keys()),
            })

            for method in methods.values():
                method_dict = {}
                method_dict['functionName'] = method.name
                method_dict['functionSourceFile'] = method.class_interface.name
                method_dict['functionLinenumber'] = method.start_line
                method_dict['functionLinenumberEnd'] = method.end_line
                method_dict['linkageType'] = ''
                method_dict['func_position'] = {
                    'start': method.start_line,
                    'end': method.end_line
                }
                method_dict['CyclomaticComplexity'] = 0
                method_dict['EdgeCount'] = method_dict['CyclomaticComplexity']
                method_dict['ICount'] = 0
                method_dict['argNames'] = method.arg_names
                method_dict['argTypes'] = method.arg_types
                method_dict['argCount'] = len(method_dict['argTypes'])
                method_dict['returnType'] = ''
                method_dict['BranchProfiles'] = []
                method_dict['Callsites'] = []
                method_dict['functionUses'] = 0
                method_dict['functionDepth'] = 0
                method_dict['constantsTouched'] = []
                method_dict['BBCount'] = 0
                method_dict['signature'] = method.name
                callsites = []
                reached = set()
                for cs_dst, _ in callsites:
                    reached.add(cs_dst)
                method_dict['functionsReached'] = list(reached)

                # Handles Java method properties
                java_method_info = {}
                java_method_info['exceptions'] = []
                java_method_info['interfaces'] = []
                java_method_info['classFields'] = []
                java_method_info['argumentGenericTypes'] = []
                java_method_info['returnValueGenericType'] = ''
                java_method_info['superClass'] = ''
                java_method_info['needClose'] = False
                java_method_info['static'] = method.static
                java_method_info['public'] = method.public
                java_method_info[
                    'classPublic'] = method.class_interface.class_public
                java_method_info['concrete'] = method.concrete
                java_method_info[
                    'classConcrete'] = method.class_interface.class_concrete
                java_method_info['javaLibraryMethod'] = False
                java_method_info['classEnum'] = False
                method_dict['JavaMethodInfo'] = java_method_info

                method_list.append(method_dict)

        if method_list:
            report['All functions'] = {}
            report['All functions']['Elements'] = method_list

        with open(report_name, 'w', encoding='utf-8') as f:
            f.write(yaml.dump(report))

    def get_source_codes_with_harnesses(self) -> list[SourceCodeFile]:
        """Gets the source codes that holds libfuzzer harnesses."""
        harnesses = []
        for source_code in self.source_code_files:
            if source_code.has_libfuzzer_harness():
                harnesses.append(source_code)

        return harnesses


class JavaMethod():
    """Wrapper for a General Declaration for method"""

    def __init__(self, root: Node, class_interface: 'JavaClassInterface'):
        self.root = root
        self.class_interface = class_interface
        self.tree_sitter_lang = self.class_interface.tree_sitter_lang
        self.parent_source = self.class_interface.parent_source

        # Store method line information
        self.start_line = self.root.start_point.row + 1
        self.end_line = self.root.end_point.row + 1

        # Other properties
        self.name = ''
        self.complexity = 0
        self.icount = 0
        self.arg_names = []
        self.arg_types = []
        self.return_type = ''
        self.sig = ''
        self.function_uses = 0
        self.function_depth = 0
        self.callsites = []
        self.public = False
        self.concrete = True
        self.static = False
        self.is_entry_method = False

        # Process method declaration
        self._process_declaration()

    def _process_declaration(self):
        """Internal helper to process the method declaration."""
        for child in self.root.children:
            # Process name
            if child.type == 'identifier':
                self.name = child.text.decode()
                if self.name == self.parent_source.entrypoint:
                    self.is_entry_method = True
                if self.class_interface.name:
                    self.name = f'[{self.class_interface.name}].{self.name}'

            # Process modifiers and annotations
            elif child.type == 'modifiers':
                for modifier in child.children:
                    if modifier.text.decode() == 'public':
                        self.public = True
                    if modifier.text.decode() == 'abstract':
                        self.concrete = False
                    if modifier.text.decode() == 'static':
                        self.static = True
                    if modifier.text.decode() == '@FuzzTest':
                        self.is_entry_method = True

            # Process arguments
            elif child.type == 'formal_parameters':
                for argument in child.children:
                    if argument.type == 'formal_parameter':
                        name = argument.child_by_field_name(
                            'name').text.decode()
                        type = argument.child_by_field_name(
                            'type').text.decode()
                        type = self.parent_source.imports.get(type, type)

                        self.arg_names.append(name)
                        self.arg_types.append(type)


class JavaClassInterface():
    """Wrapper for a General Declaration for java classes"""

    def __init__(self,
                 root: Node,
                 tree_sitter_lang: Optional[Language] = None,
                 source_code: Optional[SourceCodeFile] = None,
                 parent: Optional['JavaClassInterface'] = None):
        self.root = root
        self.parent = parent

        if parent:
            self.tree_sitter_lang = parent.tree_sitter_lang
            self.parent_source = parent.parent_source
            self.package = self.parent.name
        else:
            self.tree_sitter_lang = tree_sitter_lang
            self.parent_source = source_code
            self.package = self.parent_source.package

        # Properties
        self.name = ''
        self.class_public = False
        self.class_concrete = True
        self.is_interface = False
        self.methods = []
        self.inner_classes = []

        # Process the class/interface tree
        inner_class_nodes = self._process_node()

        # Process inner classes
        self._process_inner_classes(inner_class_nodes)

    def _process_node(self) -> list[Node]:
        """Internal helper to process the Java classes/interfaces."""
        inner_class_nodes = []

        for child in self.root.children:
            # Process modifiers
            if child.type == 'modifiers':
                for modifier in child.children:
                    if modifier.text.decode() == 'public':
                        self.class_public = True
                    if modifier.text.decode() == 'abstract':
                        self.class_concrete = False

            # Process modifiers for interface
            elif child.type == 'interface':
                self.is_interface = True
                self.class_concrete = False

            # Process name
            elif child.type == 'identifier':
                self.name = child.text.decode()
                if self.package:
                    self.name = f'{self.package}.{self.name}'

            # Process body
            elif child.type == 'class_body' or child.type == 'interface_body':
                for body in child.children:
                    # Process methods
                    if body.type == 'method_declaration':
                        self.methods.append(JavaMethod(body, self))

                    # Process inner classes or interfaces
                    elif body.type == 'class_declaration' or body.type == 'interface_declaration':
                        inner_class_nodes.append(body)

        return inner_class_nodes

    def _process_inner_classes(self, inner_class_nodes: list[Node]):
        """Internal helper to recursively process inner classes"""
        for node in inner_class_nodes:
            self.inner_classes.append(
                JavaClassInterface(node, None, None, self))

    def get_all_methods(self) -> list[JavaMethod]:
        all_methods = self.methods
        for inner_class in self.inner_classes:
            all_methods.extend(inner_class.get_all_methods())

        return all_methods

    def get_entry_method_name(self) -> str:
        """Get the entry method name for this class.
        It can be the provided entrypoint of method with @FuzzTest annotation."""
        for method in self.get_all_methods():
            if method.is_entry_method:
                return method.name

    def has_libfuzzer_harness(self) -> bool:
        """Returns whether the source code holds a libfuzzer harness"""
        if any(method.is_entry_method for method in self.get_all_methods()):
            return True

        return False

    def has_function_definition(self, target_name: str) -> bool:
        """Returns if the source file holds a given function definition."""
        if any(method.name == target_name
               for method in self.get_all_methods()):
            return True

        return False


def capture_source_files_in_tree(directory_tree: str) -> list[str]:
    """Captures source code files in a given directory."""
    exclude_directories = [
        'target', 'test', 'node_modules', 'aflplusplus', 'honggfuzz',
        'inspector', 'libfuzzer'
    ]
    language_extensions = ['.java']
    language_files = []
    for dirpath, _, filenames in os.walk(directory_tree):
        # Skip some non project directories
        if any(exclude in dirpath for exclude in exclude_directories):
            continue

        for filename in filenames:
            if pathlib.Path(filename).suffix in language_extensions:
                language_files.append(os.path.join(dirpath, filename))
    return language_files


def load_treesitter_trees(source_files: list[str],
                          entrypoint: str,
                          is_log: bool = True) -> list[SourceCodeFile]:
    """Creates treesitter trees for all files in a given list of source files."""
    results = []

    for code_file in source_files:
        source_cls = SourceCodeFile(code_file, entrypoint)
        if is_log:
            if source_cls.has_libfuzzer_harness():
                logger.info('harness: %s', code_file)
        results.append(source_cls)

    return results


def analyse_source_code(source_content: str) -> SourceCodeFile:
    """Returns a source abstraction based on a single source string."""
    source_code = SourceCodeFile(source_file='in-memory string',
                                 source_content=source_content.encode())
    return source_code
