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
"""Fuzz Introspector Light frontend"""

import os
import pathlib

import logging

from tree_sitter import Language, Parser
import tree_sitter_c
import yaml

from typing import Any

logger = logging.getLogger(name=__name__)

tree_sitter_languages = {'c': Language(tree_sitter_c.language())}

language_parsers = {'c': Parser(Language(tree_sitter_c.language()))}


class Project():
    """Wrapper for doing analysis of a collection of source files."""

    def __init__(self, source_code_files):
        self.source_code_files = source_code_files

    def dump_module_logic(self,
                          report_name,
                          entry_function: str = '',
                          harness_source: str = ''):
        """Dumps the data for the module in full."""
        logger.info('Dumping project-wide logic.')
        report: dict[str, Any] = {'report': 'name'}
        report['sources'] = []

        # Log entry function if provided
        if entry_function:
            report['Fuzzing method'] = entry_function

        report['Fuzzer filename'] = harness_source

        # Find all functions
        function_list = []
        included_header_files = set()
        for source_code in self.source_code_files:
            source_code.extract_imported_header_files()
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

            for func_def in source_code.func_defs:

                if harness_source:
                    if func_def.name(
                    ) == 'LLVMFuzzerTestOneInput' and source_code.source_file != harness_source:
                        continue
                func_dict = {}
                func_dict['functionName'] = func_def.name()
                func_dict['functionSourceFile'] = source_code.source_file
                func_dict[
                    'functionLinenumber'] = source_code.root.start_point.row
                func_dict[
                    'functionLinenumberEnd'] = source_code.root.end_point.row
                func_dict['linkageType'] = ''
                func_dict['func_position'] = {
                    'start': source_code.root.start_point.row,
                    'end': source_code.root.end_point.row,
                }
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

    def get_source_codes_with_harnesses(self):
        """Gets the source codes that holds libfuzzer harnesses."""
        harnesses = []
        for source_code in self.source_code_files:
            if source_code.has_libfuzzer_harness():
                harnesses.append(source_code)
        return harnesses

    def get_source_code_with_target(self, target_func_name):
        for source_code in self.source_code_files:
            tfunc = source_code.get_function_node(target_func_name)
            if not tfunc:
                continue
            return source_code
        return None

    def extract_calltree(self,
                         source_code=None,
                         function=None,
                         visited_functions=None,
                         depth=0,
                         line_number=-1):
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

    def find_source_with_func_def(self, target_function_name):
        """Finds the source code with a given function."""
        source_codes_with_target = []
        for source_code in self.source_code_files:
            if source_code.has_function_definition(target_function_name):
                source_codes_with_target.append(source_code)

        if len(source_codes_with_target) == 1:
            # We hav have, in this case it's trivial.
            return source_codes_with_target[0]

        return None

    def get_function(self, target_function_name):
        """Gets the first instance of a given function."""

        for source_code in self.source_code_files:
            func = source_code.get_function_node(target_function_name)
            if func is not None:
                return func
        return None


class FunctionDefinition():
    """Wrapper for a function definition"""

    def __init__(self, root, tree_sitter_lang, source_code):
        self.root = root
        self.tree_sitter_lang = tree_sitter_lang
        self.parent_source = source_code

    def name(self):
        """Gets name of a function"""
        function_name = ''
        name_node = self.root
        while name_node.child_by_field_name('declarator') is not None:
            name_node = name_node.child_by_field_name('declarator')
            # Assign function name here because we want to make sure that there is a
            # declarator when defining the name.
            function_name = name_node.text.decode()
        return function_name

    def get_return_type(self):
        """Gets a function's return type as a string"""
        ret_type = self.root.child_by_field_name('type').text.decode()
        tmp_decl = self.root
        while tmp_decl.child_by_field_name(
                'declarator').type == 'pointer_declarator':
            ret_type += '*'
            tmp_decl = tmp_decl.child_by_field_name('declarator')
        return ret_type

    def position(self):
        """Gets the byte position of the root node"""
        return self.root.byte_range

    def get_function_complexity(self):
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

        def _traverse_node_complexity(node):
            count = 0
            if node.type in branch_nodes:
                count += 1
            for item in node.children:
                count += _traverse_node_complexity(item)
            return count

        return _traverse_node_complexity(self.root)

    def get_function_instr_count(self):
        """Returns a pseudo measurement of instruction count."""

        instr_nodes = [
            "binary_expression",
            "unary_expression",
            "call_expression",
            "compound_statement",
            "assignment_expression",
        ]

        def _traverse_node_instr_count(node):
            count = 0
            if node.type in instr_nodes:
                count += 1
            for item in node.children:
                count += _traverse_node_instr_count(item)
            return count

        return _traverse_node_instr_count(self.root)

    def get_function_arg_names(self):
        """Gets the same of a function's arguments"""
        param_names = []
        parameters_node = self.root.child_by_field_name(
            'declarator').child_by_field_name('parameters')
        if not parameters_node:
            return param_names

        for param in parameters_node.children:
            if not param.is_named:
                continue

            param_tmp = param
            while param_tmp.child_by_field_name('declarator') is not None:
                param_tmp = param_tmp.child_by_field_name('declarator')
            param_names.append(param_tmp.text.decode())

        return param_names

    def get_function_arg_types(self):
        """Gets the text of a function's types"""
        param_types = []

        parameters_node = self.root.child_by_field_name(
            'declarator').child_by_field_name('parameters')

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

    def get_function_return_type(self):
        """Gets a function's return type as a string"""
        ret_type = self.root.child_by_field_name('type').text.decode()

        tmp_decl = self.root
        while tmp_decl.child_by_field_name(
                'declarator').type == 'pointer_declarator':
            ret_type += '*'
            tmp_decl = tmp_decl.child_by_field_name('declarator')

        return ret_type

    def function_signature(self):
        """Returns the function signature of a function as a string."""

        function_signature = ''
        for child_idx in range(len(self.root.children)):
            child = self.root.child(child_idx)
            if child.is_named:
                if self.root.field_name_for_child(child_idx) == 'body':
                    break
            try:
                function_signature += child.text.decode() + ' '
            except UnicodeDecodeError:
                pass
        function_signature = function_signature.replace('\n',
                                                        '').replace('\\n', '')
        while '  ' in function_signature:
            function_signature = function_signature.replace('  ', ' ')
        return function_signature

    def detailed_callsites(self):
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

    def callsites(self):
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

    def __init__(self, source_file, language, source_content=""):
        self.source_file = source_file
        self.language = language
        self.parser = language_parsers.get(self.language)
        self.tree_sitter_lang = tree_sitter_languages[self.language]

        self.root = None
        self.function_names = []
        self.line_range_pairs = []
        self.struct_defs = []
        self.typedefs = []
        self.includes = set()

        if source_content:
            self.source_content = source_content
        else:
            with open(self.source_file, 'rb') as f:
                self.source_content = f.read()

        # List of function definitions in the source file.
        self.func_defs = []

        # Initialization ruotines
        self.load_tree()

        # Load function definitions
        self._set_function_defintions()
        self.extract_types()

    def load_tree(self) -> None:
        """Load the the source code into a treesitter tree, and set
        the root node."""
        if self.language == 'c' and not self.root:
            self.root = self.parser.parse(self.source_content).root_node

    def extract_types(self):
        """Extracts the types of the source code"""
        # Extract all structs
        struct_query = self.tree_sitter_lang.query('( struct_specifier ) @sp')
        struct_query_res = struct_query.captures(self.root)
        for _, structs in struct_query_res.items():
            for struct in structs:
                if struct.child_by_field_name('body') is None:
                    continue
                if struct.child_by_field_name('name') is None:
                    continue
                # Go through each of the field declarations
                fields = []
                for child in struct.child_by_field_name('body').children:
                    if not child.child_by_field_name('declarator'):
                        continue
                    if child.type == 'field_declaration':
                        fields.append({
                            'type':
                            child.child_by_field_name('type').text.decode(),
                            'name':
                            child.child_by_field_name(
                                'declarator').text.decode()
                        })
                self.struct_defs.append({
                    'name':
                    struct.child_by_field_name('name').text.decode(),
                    'fields':
                    fields,
                    'pos': {
                        'line_start': struct.start_point.row,
                        'line_end': struct.end_point.row,
                    }
                })

        type_query = self.tree_sitter_lang.query('( type_definition ) @tp')
        type_query_res = type_query.captures(self.root)
        for _, types in type_query_res.items():
            for typedef in types:
                print(typedef.text.decode())
                # Skip if this is an anonymous struct.
                # TODO(David): handle this
                if typedef.child_by_field_name('declarator') is None:
                    continue
                typedef_struct = {
                    'name':
                    typedef.child_by_field_name('declarator').text.decode()
                }

                typedef_struct['pos'] = {
                    'line_start': typedef.start_point.row,
                    'line_end': typedef.end_point.row,
                }
                typedef_type = typedef.child_by_field_name('type')
                if typedef_type.type == 'struct_specifier':
                    if typedef.child_by_field_name('name') is not None:
                        typedef_struct[
                            'type'] = typedef_type.child_by_field_name(
                                'name').text.decode()
                    # TODO(David): handle the else branch here.
                elif typedef_type.type == 'primitive_type':
                    typedef_struct['type'] = typedef_type.text.decode()
                elif typedef_type.type == 'sized_type_specifier':
                    typedef_struct['type'] = typedef_type.text.decode()

                self.typedefs.append(typedef_struct)

    def extract_imported_header_files(self):
        """Sets the header files imported by a given module."""
        if not self.root:
            return
        include_query_str = '( preproc_include ) @imp'
        include_query = self.tree_sitter_lang.query(include_query_str)
        include_query_res = include_query.captures(self.root)

        for _, includes in include_query_res.items():
            for include in includes:
                include_path_node = include.child_by_field_name('path')
                include_path = include_path_node.text.decode().replace(
                    '"', '').replace('>', '').replace('<', '')
                self.includes.add(include_path)

    def _set_function_defintions(self):
        func_def_query_str = '( function_definition ) @fd '
        func_def_query = self.tree_sitter_lang.query(func_def_query_str)

        function_res = func_def_query.captures(self.root)
        for _, funcs in function_res.items():
            for func in funcs:
                self.func_defs.append(
                    FunctionDefinition(func, self.tree_sitter_lang, self))

    def get_defined_function_names(self):
        """Gets the functions defined in the file, as a list of strings."""
        func_names = []
        for func in self.func_defs:
            func_names.append(func.name())
        return func_names

    def get_function_node(self, target_function_name):
        """Gets the tree-sitter node corresponding to a function."""

        # Find the first instance of the function name
        for func in self.func_defs:
            if func.name() == target_function_name:
                return func
        return None

    def has_libfuzzer_harness(self) -> bool:
        """Returns whether the source code holds a libfuzzer harness"""
        for func in self.func_defs:
            if 'LLVMFuzzerTestOneInput' in func.name():
                return True

        return False

    def has_function_definition(self, target_function_name):
        """Returns if the source file holds a given function definition."""

        for func in self.func_defs:
            if func.name() == target_function_name:
                return True
        return False

    def get_linenumber(self, bytepos):
        """Gets the line number corresponding to a byte range."""

        # TODO(David): fix up encoding issues.
        if not self.line_range_pairs:
            source_content = self.source_content.decode()
            payload_range = 1
            for line in source_content.split('\n'):
                end_line_pos = payload_range + len(line) + 1
                self.line_range_pairs.append((payload_range, end_line_pos))
                payload_range = end_line_pos

        lineno = 1
        for start, end in self.line_range_pairs:
            if bytepos >= start and bytepos <= end:
                return lineno
            lineno += 1

        return -1


def capture_source_files_in_tree(directory_tree, language):
    """Captures source code files in a given directory."""
    language_extensions = {'c': ['.c', '.h']}
    language_files = []
    paths_to_avoid = [
        '/src/aflplusplus', '/src/honggfuzz', '/src/libfuzzer', '/src/fuzztest'
    ]

    for dirpath, _dirnames, filenames in os.walk(directory_tree):
        if any([x for x in paths_to_avoid if dirpath.startswith(x)]):
            continue
        for filename in filenames:
            for extensions in language_extensions[language]:
                if pathlib.Path(filename).suffix in extensions:
                    language_files.append(os.path.join(dirpath, filename))
    return language_files


def load_treesitter_trees(source_files, log_harnesses=True):
    """Creates treesitter trees for all files in a given list of source files."""
    results = []

    for language in source_files:
        if language == 'c':
            for code_file in source_files[language]:
                if not os.path.isfile(code_file):
                    continue
                source_cls = SourceCodeFile(code_file, language)
                if log_harnesses:
                    if source_cls.has_libfuzzer_harness():
                        logger.info('harness: %s', code_file)
                results.append(source_cls)
    return results


def analyse_source_code(source_content: str) -> SourceCodeFile:
    """Returns a source abstraction based on a single source string."""
    source_code = SourceCodeFile(source_file='in-memory string',
                                 language='c',
                                 source_content=source_content.encode())
    return source_code


def analyse_folder(folder_path: str, language: str = 'c') -> Project:
    """Constructs a project based on the source code in a folder."""
    source_files = {}
    source_files[language] = capture_source_files_in_tree(
        folder_path, language)
    source_codes = load_treesitter_trees(source_files)
    project = Project(source_codes)
    return project
