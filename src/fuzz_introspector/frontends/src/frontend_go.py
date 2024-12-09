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

from typing import List, Optional, Set, Tuple

import os
import pathlib
import argparse

import logging

from tree_sitter import Language, Parser, Node
import tree_sitter_go
import yaml

logger = logging.getLogger(name=__name__)
LOG_FMT = '%(asctime)s.%(msecs)03d %(levelname)s %(module)s - %(funcName)s: %(message)s'


class Project():
    """Wrapper for doing analysis of a collection of source files."""

    def __init__(self, source_code_files: list[str]):
        self.source_code_files = source_code_files

    def dump_module_logic(self, report_name: str):
        """Dumps the data for the module in full."""
        logger.info('Dumping project-wide logic.')
        report = {'report': 'name'}
        report['sources'] = []

        # Find all functions
        function_list = []
        included_header_files = set()
        for source_code in self.source_code_files:
            for incl in source_code.includes:
                included_header_files.add(incl)

            report['sources'].append({
                'source_file':
                source_code.source_file,
                'function_names':
                source_code.get_defined_function_names(),
                'types': {
                    'structs': source_code.struct_defs,
                    'typedefs': source_code.typedefs
                }
            })

            for func_def in (source_code.functions + source_code.methods):
                func_dict = {}
                start, end = func_def.get_start_end_line()
                func_dict['functionName'] = func_def.name()
                func_dict['functionSourceFile'] = source_code.source_file
                func_dict['functionLinenumber'] = start
                func_dict['functionLinbernumberEnd'] = end
                func_dict['linkageType'] = ''
                func_dict['func_position'] = {'start': start, 'end': end}
                cc_str = 'CyclomaticComplexity'
                func_dict[cc_str] = func_def.get_function_complexity()
                func_dict['EdgeCount'] = func_dict['CyclomaticComplexity']
                func_dict['ICount'] = func_def.get_function_instr_count()
                func_dict['argNames'] = func_def.get_function_arg_names()
                func_dict['argTypes'] = func_def.get_function_arg_types()
                func_dict['argCount'] = len(func_dict['argTypes'])
                func_dict['returnType'] = func_def.get_function_return_type()
                func_dict['BranchProfiles'] = []
                func_dict['functionUses'] = []
                func_dict['Callsites'] = func_def.detailed_callsites()
                func_dict['functionDepth'] = 0
                func_dict['constantsTouched'] = []
                func_dict['BBCount'] = 0

                func_dict['signature'] = func_def.function_signature()
                func_callsites = func_def.callsites()
                funcs_reached = set()
                for cs_dst, _ in func_callsites:
                    funcs_reached.add(cs_dst)
                func_dict['functionsReached'] = list(funcs_reached)

                function_list.append(func_dict)

        if function_list:
            report['All functions'] = {}
            report['All functions']['Elements'] = function_list
        report['included-header-files'] = list(included_header_files)

        with open(report_name, 'w', encoding='utf-8') as f:
            f.write(yaml.dump(report))

    def get_source_codes_with_harnesses(self) -> list['SourceCodeFile']:
        """Gets the source codes that holds libfuzzer harnesses."""
        harnesses = []
        for source_code in self.source_code_files:
            if source_code.has_libfuzzer_harness():
                harnesses.append(source_code)
        return harnesses

    def get_source_code_with_target(self, target_func_name: str) -> Optional['SourceCodeFile']:
        for source_code in self.source_code_files:
            tfunc = source_code.get_function_node(target_func_name)
            if not tfunc:
                continue
            return source_code
        return None

    def extract_calltree(self,
                         source_code: Optional['SourceCodeFile'] = None,
                         function: str = None,
                         visited_functions: set[str] = None,
                         depth: int = 0,
                         line_number: int = -1) -> str:
        """Extracts calltree string of a calltree so that FI core can use it."""
        # Create calltree from a given function
        # Find the function in the source code
        if not visited_functions:
            visited_functions = set()

        if not function:
            function = source_code.get_entry_function_name()

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
        if not func:
            return line_to_print

        callsites = func.callsites()

        if function in visited_functions:
            return line_to_print

        visited_functions.add(function)
        for cs, byte_range in callsites:
            line_number = source_code.get_linenumber(byte_range[0])
            line_to_print += self.extract_calltree(
                function=cs,
                visited_functions=visited_functions,
                depth=depth + 1,
                line_number=line_number)
        return line_to_print

    def find_source_with_func_def(self, target_function_name: str) -> Optional['SourceCodeFile']:
        """Finds the source code with a given function."""
        source_codes_with_target = []
        for source_code in self.source_code_files:
            if source_code.has_function_definition(target_function_name):
                source_codes_with_target.append(source_code)

        if len(source_codes_with_target) == 1:
            # We hav have, in this case it's trivial.
            return source_codes_with_target[0]

        return None


class FunctionMethod():
    """Wrapper for a General Declaration for function/method"""

    def __init__(self, root: Node, tree_sitter_lang: Language, source_code: 'SourceCodeFile', is_function: bool):
        self.root = root
        self.tree_sitter_lang = tree_sitter_lang
        self.parent_source = source_code
        self.is_function = is_function

    def name(self) -> str:
        """Gets name of a function"""
        function_name = ''
        name_node = self.root
        while name_node.child_by_field_name('name') is not None:
            name_node = name_node.child_by_field_name('name')
            # Assign function name here because we want to make sure that there is a
            # declarator when defining the name.
            function_name = name_node.text.decode()
        return function_name

    def get_start_end_line(self) -> (int, int):
        """Get start and end line of this function/method."""
        # Go source file line start with 0
        start = self.root.start_point.row + 1
        end = self.root.end_point.row + 1

        return (start, end)

    def get_function_complexity(self) -> int:
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

        return _traverse_node_complexity(self.root)

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

        return _traverse_node_instr_count(self.root)

    def get_function_arg_names(self) -> list[str]:
        """Gets the same of a function's arguments"""
        param_names = []
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

        return param_names

    def get_function_arg_types(self) -> list[str]:
        """Gets the text of a function's types"""
        param_types = []

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

        return param_types

    def get_function_return_type(self) -> str:
        """Gets a function's return type as a string"""
        result = self.root.child_by_field_name('result')
        if result:
            return result.text.decode()
        return ''

    def function_signature(self) -> str:
        """Returns the function signature of a function as a string."""
        # TODO IN PROGRESS
        return ''

    def detailed_callsites(self) -> list[dict[str, str]]:
        """Captures the callsite details as used by Fuzz Introspector core."""
        callsites = []
        call_query = self.tree_sitter_lang.query('( call_expression ) @ce')
        call_res = call_query.captures(self.root)
        for _, call_exprs in call_res.items():
            for call_expr in call_exprs:
                for call_child in call_expr.children:
                    if call_child.type == 'identifier':
                        src_line = call_child.start_point.row
                        src_loc = self.parent_source.source_file + ':%d,1' % (
                            src_line)
                        callsites.append({
                            'Src': src_loc,
                            'Dst': call_child.text.decode()
                        })
        return callsites

    def callsites(self) -> list[tuple[str, tuple[int, int]]]:
        """Gets the callsites of the function."""
        callsites = []
        call_query = self.tree_sitter_lang.query('( call_expression ) @ce')
        call_res = call_query.captures(self.root)
        for _, call_exprs in call_res.items():
            for call_expr in call_exprs:
                for call_child in call_expr.children:
                    if call_child.type == 'identifier':
                        callsites.append(
                            (call_child.text.decode(), call_child.byte_range))
        # Sort the callsites relative to their end position. End position
        # here makes sense to handle cases of e.g.
        # func1(func2(), func3())
        # where the execution ordering is func2 -> func3 -> func1
        callsites = list(sorted(callsites, key=lambda x: x[1][1]))

        return callsites


class SourceCodeFile():
    """Class for holding file-specific information."""

    def __init__(self, source_file: str, source_content: str = ""):
        logger.info('Processing %s' % source_file)

        self.source_file = source_file
        self.tree_sitter_lang = Language(tree_sitter_go.language())
        self.parser = Parser(self.tree_sitter_lang)

        self.root = None
        self.function_names = []
        self.struct_defs = []
        self.typedefs = []
        self.includes = set()

        if source_content:
            self.source_content = source_content
        else:
            with open(self.source_file, 'rb') as f:
                self.source_content = f.read()

        # List of function definitions in the source file.
        self.functions = []
        self.methods = []

        # Initialization ruotines
        self.load_tree()

        # Load function/method declaration
        self._set_function_declaration()
        self._set_method_declaration()

    def load_tree(self):
        """Load the the source code into a treesitter tree, and set
        the root node."""
        if not self.root:
            self.root = self.parser.parse(self.source_content).root_node

    def _set_function_declaration(self) -> list[FunctionMethod]:
        func_query_str = '( function_declaration ) @fd '
        func_query = self.tree_sitter_lang.query(func_query_str)

        function_res = func_query.captures(self.root)
        for _, funcs in function_res.items():
            for func in funcs:
                self.functions.append(
                    FunctionMethod(func, self.tree_sitter_lang, self, True))

    def _set_method_declaration(self) -> list[FunctionMethod]:
        func_query_str = '( method_declaration ) @fd '
        func_query = self.tree_sitter_lang.query(func_query_str)

        function_res = func_query.captures(self.root)
        for _, funcs in function_res.items():
            for func in funcs:
                self.methods.append(
                    FunctionMethod(func, self.tree_sitter_lang, self, False))

    def get_defined_function_names(self) -> list[str]:
        """Gets the functions defined in the file, as a list of strings."""
        func_names = []
        for func in self.functions:
            func_names.append(func.name())
        for method in self.methods:
            func_names.append(method.name())
        return func_names

    def get_function_node(self, target_function_name: str) -> FunctionMethod:
        """Gets the tree-sitter node corresponding to a function."""

        # Find the first instance of the function name
        for func in self.functions:
            if func.name() == target_function_name:
                return func

        for method in self.methods:
            if method.name() == target_function_name:
                return method

        return None

    def has_libfuzzer_harness(self) -> bool:
        """Returns whether the source code holds a libfuzzer harness"""
        if any(func.name().startswith('Fuzz') for func in self.functions):
            return True

        if any(meth.name().startswith('Fuzz') for meth in self.methods):
            return True

        return False

    def has_function_definition(self, target_function_name: str) -> bool:
        """Returns if the source file holds a given function definition."""

        if any(func.name() == target_function_name for func in self.functions):
            return True

        if any(meth.name() == target_function_name for meth in self.methods):
            return True

        return False

    def get_entry_function_name(self) -> Optional[str]:
        """Returns the entry function name of the harness if found,"""
        for func in (self.functions + self.methods):
            if func.name().startswith('Fuzz'):
                return func.name()

        return None


def capture_source_files_in_tree(directory_tree: str) -> list[str]:
    """Captures source code files in a given directory."""
    language_extensions = ['.go', '.cgo']
    language_files = []
    for dirpath, _dirnames, filenames in os.walk(directory_tree):
        for filename in filenames:
            if pathlib.Path(filename).suffix in language_extensions:
                language_files.append(os.path.join(dirpath, filename))
    return language_files


def load_treesitter_trees(source_files: list[str], log_harnesses: bool = True) -> list[SourceCodeFile]:
    """Creates treesitter trees for all files in a given list of source files."""
    results = []

    for code_file in source_files:
        source_cls = SourceCodeFile(code_file)
        if log_harnesses:
            if source_cls.has_libfuzzer_harness():
                logger.info('harness: %s', code_file)
        results.append(source_cls)

    return results
