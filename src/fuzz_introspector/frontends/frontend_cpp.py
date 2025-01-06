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

from typing import Any, Optional

import os
import pathlib
import logging

from tree_sitter import Language, Parser, Node
import tree_sitter_cpp
import yaml

logger = logging.getLogger(name=__name__)
LOG_FMT = '%(asctime)s.%(msecs)03d %(levelname)s %(module)s - %(funcName)s: %(message)s'


class SourceCodeFile():
    """Class for holding file-specific information."""

    def __init__(self,
                 source_file: str,
                 source_content: Optional[bytes] = None):
        logger.info('Processing %s' % source_file)

        self.source_file = source_file
        self.tree_sitter_lang = Language(tree_sitter_cpp.language())
        self.parser = Parser(self.tree_sitter_lang)

        self.root = None
#        self.struct_defs = []
#        self.typedefs = []
#        self.includes = set()
        self.func_defs: list['FunctionDefinition'] = []

        if source_content:
            self.source_content = source_content
        else:
            with open(self.source_file, 'rb') as f:
                self.source_content = f.read()

        if self.source_content:
            # Initialization routines
            self.load_tree()
            self.process_tree(self.root)

    def load_tree(self):
        """Load the the source code into a treesitter tree, and set
        the root node."""
        if not self.root:
            self.root = self.parser.parse(self.source_content).root_node

    def process_tree(self, node: Node, namespace: str = ''):
        """Process the node from the parsed tree."""
        for child in node.children:
            if child.type == 'function_definition':
                self._process_function_node(child, namespace)
            elif child.type == 'namespace_definition':
                self._process_namespace_node(child, namespace)
            else:
                self.process_tree(child, namespace)

    def _process_namespace_node(self, node: Node, namespace: str = ''):
        """Recursive internal helper for processing namespace definition."""
        new_namespace = node.child_by_field_name('name')
        if new_namespace:
            # Nested namespace
            if new_namespace.type == 'nested_namespace_specifier':
                for child in new_namespace.children:
                    if not child.is_named:
                        continue
                    namespace += '::' + child.text.decode()
                    if namespace.startswith('::'):
                        namespace = namespace[2:]

            # General namespace
            elif new_namespace.type == 'namespace_identifier':
                namespace += '::' + new_namespace.text.decode()
                if namespace.startswith('::'):
                    namespac = namespace[2:]

        # Continue to process the tree of the namespace
        self.process_tree(node, namespace)

    def _process_function_node(self, node: Node, namespace: str = ''):
        """Internal helper for processing function node."""
        self.func_defs.append(
            FunctionDefinition(node, self.tree_sitter_lang, self, namespace))

    def get_function_node(self, target_function_name: str, exact: bool = False):
        """Gets the tree-sitter node corresponding to a function."""

        # Find the first instance of the function name
        for func in self.func_defs:
            if func.namespace is not None:
                if func.namespace + '::' + func.name == target_function_name:
                    return func
            else:
                if func.name == target_function_name:
                    return func

        if exact:
            return None

        for func in self.func_defs:

            if func.name == target_function_name:
                return func

        for func in self.func_defs:
            if func.name == target_function_name.split('::')[-1]:
                return func
        return None

    def has_function_definition(self, target_function_name: str, exact: bool = False):
        """Returns if the source file holds a given function definition."""

        if self.get_function_node(target_function_name, exact):
            return True
        return False

    def has_libfuzzer_harness(self) -> bool:
        """Returns whether the source code holds a libfuzzer harness"""
        for func in self.func_defs:
            if 'LLVMFuzzerTestOneInput' in func.name:
                return True

        return False


class FunctionDefinition():
    """Wrapper for a function definition"""

    def __init__(
        self, root: Node,
        tree_sitter_lang: Language,
        source_code: 'SourceCodeFile',
        namespace: str):
        self.root = root
        self.tree_sitter_lang = tree_sitter_lang
        self.parent_source = source_code
        self.namespace = namespace

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
        self.callsites: list[tuple[str, int]] = []

        # Extract information from tree-sitter node
        self._extract_information()

    def _extract_information(self):
        """Extract information from tree-sitter node."""
        # Extract function name
        name_node = self.root
        while name_node.child_by_field_name('declarator') is not None:
            name_node = name_node.child_by_field_name('declarator')
            self.name = name_node.text.decode()

    def extract_callsites(self):
        """Gets the callsites of the function."""
        callsites = []
        call_query = self.tree_sitter_lang.query('( call_expression ) @ce')
        call_res = call_query.captures(self.root)
        for _, call_exprs in call_res.items():
            for call_expr in call_exprs:

                tmp_node = call_expr.child_by_field_name('function')

                function_call = ''
                # Handle callsites where the scope is not None, e.g.
                # ns1::ns2::func1(...);
                if tmp_node.child_by_field_name('scope'):
                    while tmp_node.child_by_field_name('name') is not None:
                        # TODO(David) handle
                        if tmp_node.child_by_field_name(
                                'name').type == 'identifier':
                            if tmp_node.child_by_field_name('scope'):
                                function_call += tmp_node.child_by_field_name(
                                    'scope').text.decode() + '::'
                            function_call += tmp_node.child_by_field_name(
                                'name').text.decode()
                            break

                        if not tmp_node.child_by_field_name('scope'):
                            logger.info('Missing analysis: %s',
                                        tmp_node.text.decode())
                            function_call = ''
                            break
                        function_call += tmp_node.child_by_field_name(
                            'scope').text.decode() + '::'

                        tmp_node = tmp_node.child_by_field_name('name')
                    if not function_call:
                        continue
                # Handle non-scoped function calls
                if tmp_node.type == 'identifier':
                    function_call = tmp_node.text.decode()

                callsites.append((function_call, call_expr.byte_range))

        # Sort the callsites relative to their end position. End position
        # here makes sense to handle cases of e.g.
        # func1(func2(), func3())
        # where the execution ordering is func2 -> func3 -> func1
        callsites = list(sorted(callsites, key=lambda x: x[1][1]))

        self.callsites = callsites


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

        self.all_functions = {}
        for source_code in self.source_code_files:
            # Log entry method if provided
            report['Fuzzing method'] = 'LLVMFuzzerTestOneInput'

            # Retrieve project information
            func_names = [func.name for func in source_code.func_defs]
            report['sources'].append({
                'source_file': source_code.source_file,
                'function_names': func_names,
            })

            # Obtain all functions of the project
            source_code_functions = {
                func.name: func
                for func in source_code.func_defs
            }

            self.all_functions.update(source_code_functions)

        # Process all project functions
        func_list = []
        for func in self.all_functions.values():
            func.extract_callsites()

            func_dict: dict[str, Any] = {}
            func_dict['functionName'] = func.name
            func_dict['functionSourceFile'] = func.parent_source.source_file
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

    def get_source_codes_with_harnesses(self) -> list[SourceCodeFile]:
        """Gets the source codes that holds libfuzzer harnesses."""
        harnesses = []
        for source_code in self.source_code_files:
            if source_code.has_libfuzzer_harness():
                harnesses.append(source_code)
        return harnesses

    def extract_calltree(self,
                         source_file: str,
                         source_code: Optional[SourceCodeFile] = None,
                         function: Optional[str] = None,
                         visited_functions: Optional[set[str]] = None,
                         depth: int = 0,
                         line_number: int = -1) -> str:
        """Extracts calltree string of a calltree so that FI core can use it."""
        # Create calltree from a given function
        # Find the function in the source code
        if not visited_functions:
            visited_functions = set()

        if not function:
            return ''

        line_to_print = '  ' * depth
        line_to_print += function
        line_to_print += ' '

        if not source_code:
            source_code = self.find_source_with_func_def(function)
        if source_code:
            line_to_print += source_code.source_file

        line_to_print += ' '
        line_to_print += str(line_number)

        line_to_print += '\n'
        if not source_code:
            return line_to_print

        func = source_code.get_function_node(function)
        callsites = func.callsites

        if function in visited_functions:
            return line_to_print

        visited_functions.add(function)
        for cs, byte_range in callsites:
            line_number = 0
            line_to_print += self.extract_calltree(
                source_file=source_file,
                function=cs,
                visited_functions=visited_functions,
                depth=depth + 1,
                line_number=line_number)
        return line_to_print

    def find_source_with_func_def(self, target_function_name):
        """Finds the source code with a given function."""

        source_codes_with_target = []
        for source_code in self.source_code_files:
            if source_code.has_function_definition(target_function_name,
                                                   exact=True):
                source_codes_with_target.append(source_code)

        if len(source_codes_with_target) == 1:
            # We hav have, in this case it's trivial.
            return source_codes_with_target[0]

        source_codes_with_target = []
        for source_code in self.source_code_files:
            if source_code.has_function_definition(target_function_name,
                                                   exact=False):
                source_codes_with_target.append(source_code)
        if len(source_codes_with_target) == 1:
            # We hav have, in this case it's trivial.
            return source_codes_with_target[0]
        if len(source_codes_with_target) > 1:
            print("We have more than a single source %s" %
                  (target_function_name))
            for sc in source_codes_with_target:
                print("- %s" % (sc.source_file))
        return None


def capture_source_files_in_tree(directory_tree):
    """Captures source code files in a given directory."""
    language_files = []
    language_extensions = [
        '.cpp', '.cc', '.c++', '.cxx', '.h', '.hpp', '.hh', '.hxx', '.inl'
    ]
    exclude_directories = [
        'build', 'target', 'tests', 'node_modules', 'aflplusplus', 'honggfuzz',
        'inspector', 'libfuzzer', 'fuzztest'
    ]

    for dirpath, _, filenames in os.walk(directory_tree):
        # Skip some non project directories
        if any(exclude in dirpath for exclude in exclude_directories):
            continue

        for filename in filenames:
            if pathlib.Path(filename).suffix.lower() in language_extensions:
                language_files.append(os.path.join(dirpath, filename))

    return language_files


def load_treesitter_trees(source_files, is_log=True):
    """Creates treesitter trees for all files in a given list of source files."""
    results = []

    for code_file in source_files:
        if not os.path.isfile(code_file):
            continue

        source_cls = SourceCodeFile(code_file)
        results.append(source_cls)

        if is_log:
            if source_cls.has_libfuzzer_harness():
                logger.info('harness: %s', code_file)

    return results


def analyse_source_code(source_content: str) -> SourceCodeFile:
    """Returns a source abstraction based on a single source string."""
    source_code = SourceCodeFile(source_file='in-memory string',
                                 source_content=source_content.encode())
    return source_code
