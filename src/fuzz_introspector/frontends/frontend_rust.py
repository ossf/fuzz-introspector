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
"""Fuzz Introspector Light frontend for Rust"""

from typing import Any, Optional

import os
import pathlib
import logging

from tree_sitter import Language, Parser, Node
import tree_sitter_rust
import yaml

logger = logging.getLogger(name=__name__)
LOG_FMT = '%(asctime)s.%(msecs)03d %(levelname)s %(module)s - %(funcName)s: %(message)s'


class SourceCodeFile():
    """Class for holding file-specific information."""

    def __init__(self,
                 source_file: str,
                 source_content: Optional[bytes] = None):
        logger.info('Processing %s' % source_file)

        self.root = None
        self.entrypoint = None
        self.source_file = source_file
        self.tree_sitter_lang = Language(tree_sitter_rust.language())
        self.parser = Parser(self.tree_sitter_lang)

        if source_content:
            self.source_content = source_content
        else:
            with open(self.source_file, 'rb') as f:
                self.source_content = f.read()

        # Definition initialisation
        self.functions: list['RustFunction'] = []

        # Initialization ruotines
        self.load_tree()

        # Load functions/methods delcaration
        self._set_function_method_declaration()

        print(f'{source_file}:{len(self.functions)}')

    def load_tree(self):
        """Load the the source code into a treesitter tree, and set
        the root node."""
        self.root = self.parser.parse(self.source_content).root_node

    def _set_function_method_declaration(self):
        """Internal helper for retrieving all classes."""
        for node in self.root.children:

            # Handle general functions
            if node.type == 'function_item':
                self.functions.append(
                    RustFunction(node, self.tree_sitter_lang, self))

            # Handle impl methods
            elif node.type == 'impl_item':
                impl_body = node.child_by_field_name('body')
                for impl in impl_body.children:
                    if impl.type == 'function_item':
                        self.functions.append(
                            RustFunction(impl, self.tree_sitter_lang, self, node))

            # Handle mod functions
            elif node.type == 'mod_item':
                mod_body = node.child_by_field_name('body')
                if mod_body:
                    for mod in mod_body.children:
                        if mod.type == 'function_item':
                            self.functions.append(
                                RustFunction(mod, self.tree_sitter_lang, self, mod=node))

            # Handling for fuzzing harness entry point macro invocation
            elif node.type == 'expression_statement':
                for macro in node.children:
                    if macro.type == 'macro_invocation':
                        rust_function = RustFunction(
                            macro, self.tree_sitter_lang, self, is_macro=True)

                        # Only consider the macro as function if it is the
                        # fuzzing entry point (fuzz_target macro)
                        if rust_function.is_entry_method:
                            self.functions.append(rust_function)

    def has_libfuzzer_harness(self) -> bool:
        """Returns whether the source code holds a libfuzzer harness"""
        if any(func.is_entry_method for func in self.functions):
            return True

        return False

    def get_entry_method_name(self) -> Optional[str]:
        """Returns the entry method name of the harness if found."""
        if self.has_libfuzzer_harness():
            for func in self.functions:
                if func.is_entry_method:
                    return func.name

        return None


class RustFunction():
    """Wrapper for a General Declaration for function"""

    def __init__(self,
                 root: Node,
                 tree_sitter_lang: Optional[Language] = None,
                 source_code: Optional[SourceCodeFile] = None,
                 impl: Optional[Node] = None,
                 mod: Optional[Node] = None,
                 is_macro: bool = False):
        self.root = root
        self.tree_sitter_lang = tree_sitter_lang
        self.parent_source = source_code
        self.impl = impl
        self.mod = mod
        self.is_macro = is_macro

        # Store method line information
        self.start_line = self.root.start_point.row + 1
        self.end_line = self.root.end_point.row + 1

        # Other properties
        self.name = ''
        self.complexity = 0
        self.icount = 0
        self.arg_names: list[str] = []
        self.arg_types: list[str] = []
        self.return_type = ''
        self.sig = ''
        self.function_uses = 0
        self.function_depth = 0
        self.base_callsites: list[tuple[str, int]] = []
        self.detailed_callsites: list[dict[str, str]] = []
        self.is_entry_method = False

        # Process method declaration
        if is_macro:
            self._process_macro_declaration()
        else:
            self._process_declaration()

    def _process_declaration(self):
        """Internal helper to process the function/method declaration."""
        # Process name
        self.name = self.root.child_by_field_name('name').text.decode()

        # Process return type
        return_type = self.root.child_by_field_name('return_type')
        if return_type:
            self.return_type = return_type.text.decode()
        else:
            self.return_type = 'void'

        # Process arguments
        parameters = self.root.child_by_field_name('parameters')
        for param in parameters.children:
            if param.type == 'parameter':
                for item in param.children:
                    if item.type == 'identifier':
                        self.arg_names.append(item.text.decode())
                    elif 'type' in item.type:
                        self.arg_types.append(item.text.decode())

        # Process signature
        signature = self.root.text.decode().split('{')[0]
        self.sig = ''.join(line.strip() for line in signature.splitlines() if line.strip())

        print('@@@@@')
        print(self.sig)
        print(signature)
        print('@@@@@')

#        for child in self.root.children:
#            # Process name
#            if child.type == 'identifier':
#                self.name = child.text.decode()
#
#            print(f'{child.type}:{child.text.decode()}')

    def _process_macro_declaration(self):
        """Internal helper to process the macro declaration for fuzzing
        entry point."""
        for child in self.root.children:
            # Process name
            if child.type == 'identifier':
                self.name = child.text.decode()
                if self.name == 'fuzz_target':
                    self.is_entry_method = True

            # token_tree for body


class Project():
    """Wrapper for doing analysis of a collection of source files."""

    def __init__(self, source_code_files: list[SourceCodeFile]):
        self.source_code_files = source_code_files

    def dump_module_logic(self,
                          report_name: str,
                          harness_name: Optional[str] = None):
        """Dumps the data for the module in full."""
        logger.info('Dumping project-wide logic.')
        report: dict[str, Any] = {'report': 'name'}
        report['sources'] = []

        func_list = []
        for source_code in self.source_code_files:
            # Log entry method if provided
            entry_method = source_code.get_entry_method_name()
            if entry_method:
                report['Fuzzing method'] = entry_method

            # Retrieve project information
            func_names = [func.name for func in source_code.functions]
            report['sources'].append({
                'source_file': source_code.source_file,
                'function_names': func_names,
            })

            # Process all project methods
            for func in source_code.functions:
                func_dict: dict[str, Any] = {}
                func_dict['functionName'] = func.name
                func_dict['functionSourceFile'] = source_code.source_file
                func_dict['functionLinenumber'] = func.start_line
                func_dict['functionLinenumberEnd'] = func.end_line
                func_dict['linkageType'] = ''
                func_dict['func_position'] = {
                    'start': func.start_line,
                    'end': func.end_line
                }
                func_dict['CyclomaticComplexity'] = func.complexity
                func_dict['EdgeCount'] = func_dict['CyclomaticComplexity']
                func_dict['ICount'] = func.icount
                func_dict['argNames'] = func.arg_names
                func_dict['argTypes'] = func.arg_types
                func_dict['argCount'] = len(func_dict['argTypes'])
                func_dict['returnType'] = func.return_type
                func_dict['BranchProfiles'] = []
                func_dict['Callsites'] = func.detailed_callsites
                func_dict['functionUses'] = 0
                func_dict['functionDepth'] = 0
                func_dict['constantsTouched'] = []
                func_dict['BBCount'] = 0
                func_dict['signature'] = func.sig
                callsites = func.base_callsites
                reached = set()
                for cs_dst, _ in callsites:
                    reached.add(cs_dst)
                func_dict['functionsReached'] = list(reached)

                func_list.append(func_dict)

        if func_list:
            report['All functions'] = {}
            report['All functions']['Elements'] = func_list

        with open(report_name, 'w', encoding='utf-8') as f:
            f.write(yaml.dump(report))

    def extract_calltree(self,
                         source_file: str,
                         source_code: SourceCodeFile,
                         func: Optional[str] = None,
                         visited_funcs: Optional[set[str]] = None,
                         depth: int = 0,
                         line_number: int = -1) -> str:
        """Extracts calltree string of a calltree so that FI core can use it."""
        if not visited_funcs:
            visited_funcs = set()

        if not func:
            func = source_code.get_entry_method_name()

        # TODO Add calltree extraction logic

        return ''

    def get_source_codes_with_harnesses(self) -> list[SourceCodeFile]:
        """Gets the source codes that holds libfuzzer harnesses."""
        harnesses = []
        for source_code in self.source_code_files:
            if source_code.has_libfuzzer_harness():
                harnesses.append(source_code)

        return harnesses


def capture_source_files_in_tree(directory_tree: str) -> list[str]:
    """Captures source code files in a given directory."""
    exclude_directories = [
        'tests', 'examples', 'benches', 'node_modules',
        'aflplusplus', 'honggfuzz', 'inspector', 'libfuzzer'
    ]
    language_extensions = ['.rs']
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
                          is_log: bool = True) -> list[SourceCodeFile]:
    """Creates treesitter trees for all files in a given list of source files."""
    results = []

    for code_file in source_files:
        source_cls = SourceCodeFile(code_file)
        if is_log:
            if source_cls.has_libfuzzer_harness():
                logger.info('harness: %s', code_file)
        results.append(source_cls)

    return results


def analyse_source_code(source_content: str,
                        entrypoint: str) -> SourceCodeFile:
    """Returns a source abstraction based on a single source string."""
    source_code = SourceCodeFile(source_file='in-memory string',
                                 source_content=source_content.encode())
    return source_code
