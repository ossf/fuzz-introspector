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
"""Fuzz Introspector Light frontend for Go"""

from typing import Optional

import os
import pathlib
import logging

from tree_sitter import Language, Parser, Node
import tree_sitter_go
import yaml

from typing import Any

logger = logging.getLogger(name=__name__)


class SourceCodeFile():
    """Class for holding file-specific information."""

    def __init__(self,
                 source_file: str,
                 source_content: Optional[bytes] = None):
        logger.info('Processing %s', source_file)

        self.root = None
        self.imports: list[str] = []
        self.source_file = source_file
        self.tree_sitter_lang = Language(tree_sitter_go.language())
        self.parser = Parser(self.tree_sitter_lang)

        if source_content:
            self.source_content = source_content
        else:
            with open(self.source_file, 'rb') as f:
                self.source_content = f.read()

        # List of function definitions in the source file.
        self.functions: list['FunctionMethod'] = []
        self.methods: list['FunctionMethod'] = []

        # Initialization ruotines
        self.load_tree()

        # Load function/method declaration
        self._set_function_declaration()
        self._set_method_declaration()

        # Parse import package
        self._set_imports()

    def load_tree(self):
        """Load the the source code into a treesitter tree, and set
        the root node."""
        self.root = self.parser.parse(self.source_content).root_node

    def _set_function_declaration(self):
        """Internal helper for retrieving all functions."""
        func_query_str = '( function_declaration ) @fd '
        func_query = self.tree_sitter_lang.query(func_query_str)

        function_res = func_query.captures(self.root)
        for _, funcs in function_res.items():
            for func in funcs:
                self.functions.append(
                    FunctionMethod(func, self.tree_sitter_lang, self, True))

    def _set_method_declaration(self):
        """Internal helper for retrieving all methods."""
        func_query_str = '( method_declaration ) @fd '
        func_query = self.tree_sitter_lang.query(func_query_str)

        function_res = func_query.captures(self.root)
        for _, funcs in function_res.items():
            for func in funcs:
                self.methods.append(
                    FunctionMethod(func, self.tree_sitter_lang, self, False))

    def _set_imports(self):
        """Internal helper for retrieving all imports."""
        import_set = set()

        import_query_str = '( import_declaration ) @imp'
        import_query = self.tree_sitter_lang.query(import_query_str)
        import_query_res = import_query.captures(self.root)

        for _, imports in import_query_res.items():
            for imp in imports:
                for import_spec in imp.children:
                    if import_spec.type == 'import_spec_list':
                        for path in import_spec.children:
                            if path.type == 'import_spec':
                                path = path.text.decode().replace('"', '')
                                # Only store the package name, not full path
                                import_set.add(path.rsplit('/', 1)[-1])

        self.imports = list(import_set)

    def get_defined_function_names(self) -> list[str]:
        """Gets the functions defined in the file, as a list of strings."""
        func_names = []
        for func in self.functions:
            func_names.append(func.get_name())
        for method in self.methods:
            func_names.append(method.get_name())
        return func_names

    def get_function_node(
            self, target_function_name: str) -> Optional['FunctionMethod']:
        """Gets the tree-sitter node corresponding to a function."""

        # Find the first instance of the function name
        for func in self.functions:
            if func.get_name() == target_function_name:
                return func

        for method in self.methods:
            if method.get_name() == target_function_name:
                return method

        return None

    def has_libfuzzer_harness(self) -> bool:
        """Returns whether the source code holds a libfuzzer harness"""
        if any(func.get_name().startswith('Fuzz') for func in self.functions):
            return True

        if any(meth.get_name().startswith('Fuzz') for meth in self.methods):
            return True

        return False

    def has_function_definition(self, target_function_name: str) -> bool:
        """Returns if the source file holds a given function definition."""

        if any(func.get_name() == target_function_name
               for func in self.functions):
            return True

        if any(meth.get_name() == target_function_name
               for meth in self.methods):
            return True

        return False

    def get_entry_function_name(self) -> Optional[str]:
        """Returns the entry function name of the harness if found,"""
        for func in (self.functions + self.methods):
            if func.get_name().startswith('Fuzz'):
                return func.get_name()

        return None


class Project():
    """Wrapper for doing analysis of a collection of source files."""

    def __init__(self, source_code_files: list[SourceCodeFile]):
        self.source_code_files = source_code_files
        self.full_functions_methods = [
            item for src in source_code_files
            for item in src.functions + src.methods
        ]

    def dump_module_logic(self, report_name: str, entry_function: str = ''):
        """Dumps the data for the module in full."""
        logger.info('Dumping project-wide logic.')
        report: dict[str, Any] = {'report': 'name'}
        report['sources'] = []

        # Log entry function if provided
        if entry_function:
            report['Fuzzing method'] = entry_function

        # Find all functions
        function_list: list[dict[str, Any]] = []
        for source_code in self.source_code_files:
            report['sources'].append({
                'source_file':
                source_code.source_file,
                'function_names':
                source_code.get_defined_function_names(),
            })

            functions_methods = source_code.functions + source_code.methods
            for func_def in functions_methods:
                func_dict: dict[str, Any] = {}
                func_dict['functionName'] = func_def.get_name()
                func_dict['functionSourceFile'] = source_code.source_file
                func_dict['functionLinenumber'] = func_def.start_line
                func_dict['functionLinenumberEnd'] = func_def.end_line
                func_dict['linkageType'] = ''
                func_dict['func_position'] = {
                    'start': func_def.start_line,
                    'end': func_def.end_line
                }
                func_dict['CyclomaticComplexity'] = func_def.get_complexity()
                func_dict['EdgeCount'] = func_dict['CyclomaticComplexity']
                func_dict['ICount'] = func_def.get_function_instr_count()
                func_dict['argNames'] = func_def.get_function_arg_names()
                func_dict['argTypes'] = func_def.get_function_arg_types()
                func_dict['argCount'] = len(func_dict['argTypes'])
                func_dict['returnType'] = func_def.get_function_return_type()
                func_dict['BranchProfiles'] = []
                func_dict['Callsites'] = func_def.detailed_callsites()
                func_dict['functionUses'] = func_def.get_function_uses(
                    self.full_functions_methods)
                func_dict['functionDepth'] = func_def.get_function_depth(
                    self.full_functions_methods)
                func_dict['constantsTouched'] = []
                func_dict['BBCount'] = 0
                func_dict['signature'] = func_def.function_signature()
                func_callsites = func_def.base_callsites()
                funcs_reached = set()
                for cs_dst, _ in func_callsites:
                    funcs_reached.add(cs_dst)
                func_dict['functionsReached'] = list(funcs_reached)

                function_list.append(func_dict)

        if function_list:
            report['All functions'] = {}
            report['All functions']['Elements'] = function_list

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
        if not visited_functions:
            visited_functions = set()

        if not function:
            if not source_code:
                return ''
            function = source_code.get_entry_function_name()

        if not function:
            return ''

        line_to_print = '  ' * depth
        line_to_print += function
        line_to_print += ' '
        line_to_print += source_file

        if not source_code:
            source_code = self.find_source_with_func_def(function)

        line_to_print += ' '
        line_to_print += str(line_number)

        line_to_print += '\n'
        if not source_code:
            return line_to_print

        func = source_code.get_function_node(function)
        if not func:
            return line_to_print

        callsites = func.base_callsites()

        if function in visited_functions:
            return line_to_print

        visited_functions.add(function)
        for cs, line_number in callsites:
            line_to_print += self.extract_calltree(
                source_code.source_file,
                function=cs,
                visited_functions=visited_functions,
                depth=depth + 1,
                line_number=line_number)
        return line_to_print

    def find_source_with_func_def(
            self, target_function_name: str) -> Optional[SourceCodeFile]:
        """Finds the source code with a given function."""
        for source_code in self.source_code_files:
            if source_code.has_function_definition(target_function_name):
                return source_code

        return None


class FunctionMethod():
    """Wrapper for a General Declaration for function/method"""

    def __init__(self, root: Node, tree_sitter_lang: Language,
                 source_code: SourceCodeFile, is_function: bool):
        self.root = root
        self.tree_sitter_lang = tree_sitter_lang
        self.parent_source = source_code
        self.is_function = is_function

        # Go source file line start with 0
        self.start_line = self.root.start_point.row + 1
        self.end_line = self.root.end_point.row + 1

        # Other properties
        self.function_name = ''
        self.complexity = 0
        self.icount = 0
        self.arg_names: list[str] = []
        self.arg_types: list[str] = []
        self.return_type = ''
        self.sig = ''
        self.function_uses = 0
        self.function_depth = 0
        self.callsites: list[tuple[str, int]] = []

    def get_name(self) -> str:
        """Gets name of a function"""
        if not self.function_name:
            name_node = self.root
            while name_node.child_by_field_name('name') is not None:
                name_node = name_node.child_by_field_name('name')
                self.function_name = name_node.text.decode()

        return self.function_name

    def get_function_uses(self,
                          all_funcs_meths: list['FunctionMethod']) -> int:
        """Calculate how many function called this function."""
        if not self.function_uses:
            for func in all_funcs_meths:
                found = False
                for callsite in func.base_callsites():
                    if callsite[0] == self.get_name():
                        found = True
                        break
                if found:
                    self.function_uses += 1

        return self.function_uses

    def get_function_depth(self,
                           all_funcs_meths: list['FunctionMethod']) -> int:
        """Calculate function depth of this function."""

        if self.function_depth:
            return self.function_depth

        visited: list[str] = []
        func_meth_dict = {f.get_name(): f for f in all_funcs_meths}

        def _recursive_function_depth(func_meth: FunctionMethod) -> int:
            callsites = func_meth.base_callsites()
            if len(callsites) == 0:
                return 0

            visited.append(func_meth.get_name())
            depth = 0
            for callsite in callsites:
                target = func_meth_dict.get(callsite[0])
                if callsite[0] in visited:
                    depth = max(depth, 1)
                elif target:
                    depth = max(depth, _recursive_function_depth(target) + 1)
                else:
                    visited.append(callsite[0])

            return depth

        self.function_depth = _recursive_function_depth(self)
        return self.function_depth

    def get_complexity(self) -> int:
        """Gets complexity measure based on counting branch nodes in a
        function."""

        branch_nodes = [
            "if_statement",
            "case_statement",
            "do_statement",
            "for_range_loop",
            "for_statement",
            "goto_statement",
            "function_declarator",
            "pointer_declarator",
            "struct_specifier",
            "preproc_elif",
            "while_statement",
            "switch_statement",
            "&&",
            "||",
        ]

        def _traverse_node_complexity(node: Node) -> int:
            count = 0
            if node.type in branch_nodes:
                count += 1
            for item in node.children:
                count += _traverse_node_complexity(item)
            return count

        if not self.complexity:
            self.complexity = _traverse_node_complexity(self.root)

        return self.complexity

    def get_function_instr_count(self) -> int:
        """Returns a pseudo measurement of instruction count."""

        instr_nodes = [
            "binary_expression",
            "unary_expression",
            "call_expression",
            "compound_statement",
            "assignment_expression",
        ]

        def _traverse_node_instr_count(node: Node) -> int:
            count = 0
            if node.type in instr_nodes:
                count += 1
            for item in node.children:
                count += _traverse_node_instr_count(item)
            return count

        if not self.icount:
            self.icount = _traverse_node_instr_count(self.root)

        return self.icount

    def get_function_arg_names(self) -> list[str]:
        """Gets the same of a function's arguments"""
        if self.arg_names:
            return self.arg_names

        param_names: list[str] = []
        parameters_node = self.root.child_by_field_name('parameters')
        if not parameters_node:
            return param_names

        for param in parameters_node.children:
            if not param.is_named:
                continue

            param_tmp = param
            while param_tmp.child_by_field_name('name') is not None:
                param_tmp = param_tmp.child_by_field_name('name')
            param_names.append(param_tmp.text.decode())

        self.arg_names = param_names
        return self.arg_names

    def get_function_arg_types(self) -> list[str]:
        """Gets the text of a function's types"""
        if self.arg_types:
            return self.arg_types

        param_types: list[str] = []
        parameters_node = self.root.child_by_field_name('parameters')
        if not parameters_node:
            return param_types

        for param in parameters_node.children:
            if not param.is_named:
                continue

            if not param.child_by_field_name('type'):
                continue

            type_str = param.child_by_field_name('type').text.decode()
            param_tmp = param
            while param_tmp.child_by_field_name('declarator') is not None:
                if param_tmp.type == 'pointer_declarator':
                    type_str += '*'
                param_tmp = param_tmp.child_by_field_name('declarator')
            param_types.append(type_str)

        self.arg_types = param_types
        return self.arg_types

    def get_function_return_type(self) -> str:
        """Gets a function's return type as a string"""
        if not self.return_type:
            result = self.root.child_by_field_name('result')
            if result:
                self.return_type = result.text.decode()

        return self.return_type

    def function_signature(self) -> str:
        """Returns the function signature of a function as a string."""
        # Go function signature format
        # (Optional_Receiver) Func_Name(Argument_Types) Optional_Return_Type

        if not self.sig:
            # Base signature
            name = self.get_name()
            params = self.get_function_arg_types()
            self.sig = f'{name}({",".join(params)})'

            # Handles return type
            rtn_type = self.get_function_return_type()
            if rtn_type:
                self.sig = f'{self.sig} {rtn_type}'

            # Handles receiver
            receiver = self.root.child_by_field_name('receiver')
            if receiver:
                receiver_type = receiver.text.decode().split(' ')[-1][:-1]
                self.sig = f'({receiver_type}) {self.sig}'

        return self.sig

    def detailed_callsites(self) -> list[dict[str, str]]:
        """Captures the callsite details as used by Fuzz Introspector core."""
        callsites = []
        for dst, src_line in self.base_callsites():
            src_loc = self.parent_source.source_file + ':%d,1' % (src_line)
            callsites.append({'Src': src_loc, 'Dst': dst})

        return callsites

    def base_callsites(self) -> list[tuple[str, int]]:
        """Gets the callsites of the function."""
        if self.callsites:
            return self.callsites

        callsites = []
        call_query = self.tree_sitter_lang.query('( call_expression ) @ce')
        call_res = call_query.captures(self.root)
        for _, call_exprs in call_res.items():
            for call_expr in call_exprs:
                for call_child in call_expr.children:
                    # Simple call
                    if call_child.type == 'identifier':
                        callsites.append((
                            call_child.text.decode(),
                            call_child.byte_range,
                            call_child.start_point.row + 1,
                        ))

                    # Package/method call
                    if call_child.type == 'selector_expression':
                        call = call_child.text.decode()

                        # Variable call
                        split_call = call.split('.', 1)
                        if split_call[
                                0] not in self.parent_source.imports and len(
                                    split_call) > 1:
                            call = call.split('.')[-1]

                        # Chain call
                        split_call = call.rsplit(').', 1)
                        if len(split_call) > 1:
                            call = split_call[1]

                        callsites.append((
                            call,
                            call_child.byte_range,
                            call_child.start_point.row + 1,
                        ))

        callsites = sorted(callsites, key=lambda x: x[1][1])
        self.callsites = [(x[0], x[2]) for x in callsites]
        return self.callsites


def capture_source_files_in_tree(directory_tree: str) -> list[str]:
    """Captures source code files in a given directory."""
    language_extensions = ['.go', '.cgo']
    language_files = []
    for dirpath, _dirnames, filenames in os.walk(directory_tree):
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


def analyse_source_code(source_content: str) -> SourceCodeFile:
    """Returns a source abstraction based on a single source string."""
    source_code = SourceCodeFile(source_file='in-memory string',
                                 source_content=source_content.encode())
    return source_code
