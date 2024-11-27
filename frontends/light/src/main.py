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
import sys
import pathlib

from tree_sitter import Language, Parser
import tree_sitter_c
import yaml

tree_sitter_languages = {'c': Language(tree_sitter_c.language())}

language_parsers = {'c': Parser(Language(tree_sitter_c.language()))}


class Project():
    """Wrapper for doing analysis of a collection of source files."""

    def __init__(self, source_code_files):
        self.source_code_files = source_code_files

    def dump_module_logic(self, report_name):
        """Dumps the data for the module in full."""
        report = {'report': 'name'}
        report['sources'] = []

        # Find all functions
        function_list = []
        for source_code in self.source_code_files:

            report['sources'].append({
                'source_file':
                source_code.source_file,
                'function_names':
                source_code.function_names
            })

            for func_name in source_code.function_names:
                func_dict = {}
                func_dict['name'] = func_name
                func_dict['source_file'] = source_code.source_file
                start_pos, end_pos = source_code.get_function_linenumber(
                    func_name)
                func_dict['func_position'] = {
                    'start': start_pos,
                    'end': end_pos
                }

                func_callsites = source_code.get_callsites_in_function(
                    func_name)
                funcs_reached = set()
                for cs_dst, _ in func_callsites:
                    funcs_reached.add(cs_dst)
                func_dict['functionsReached'] = list(funcs_reached)

                # Get cyclomatic complexity
                func_dict[
                    'CyclomaticComplexity'] = source_code.get_function_complexity(
                        func_name)

                # Function depth

                # ICount
                func_dict['ICount'] = source_code.get_function_instr_count(
                    func_name)

                # EdgeCount
                func_dict['EdgeCount'] = func_dict['CyclomaticComplexity']

                # argCount

                # Arg names
                func_dict['ArgNames'] = source_code.get_function_arg_names(
                    func_name)

                # Arg types
                func_dict['ArgTypes'] = source_code.get_function_arg_types(
                    func_name)

                # Return type
                func_dict['ReturnType'] = source_code.get_function_return_type(
                    func_name)

                # Callsites

                func_signature = source_code.function_signature(func_name)
                func_dict['signature'] = func_signature
                function_list.append(func_dict)

        if function_list:
            report['function-list'] = function_list

        with open(report_name, 'w', encoding='utf-8') as f:
            f.write(yaml.dump(report))

    def get_source_codes_with_harnesses(self):
        """Gets the source codes that holds libfuzzer harnesses."""
        harnesses = []
        for source_code in self.source_code_files:
            if source_code.has_libfuzzer_harness():
                harnesses.append(source_code)
        return harnesses

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

        callsites = source_code.get_callsites_in_function(function)

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

        #for sc in source_codes_with_target:
        #    print('--- %s'%(sc.source_file))
        #print("Found multiple instances: %d, %s"%(len(source_codes_with_target), target_function_name))
        #for ctp in source_codes_with_target:
        #    print("-- %s"%(ctp.source_file))
        return None


class SourceCodeFile():
    """Class for holding file-specific information."""

    def __init__(self, source_file, language):
        self.source_file = source_file
        self.language = language
        self.parser = language_parsers.get(self.language)
        self.tree_sitter_lang = tree_sitter_languages[self.language]

        self.root = None
        self.function_names = []

        self.line_range_pairs = []

        # Initialization ruotines
        self.load_tree()

    def load_tree(self) -> None:
        """Load the the source code into a treesitter tree, and set
        the root node."""
        if self.language == 'c' and not self.root:
            with open(self.source_file, 'rb') as f:
                source_code = f.read()
            self.root = self.parser.parse(source_code).root_node

    def get_defined_function_names(self):
        """Gets the functions defined in the file, as a list of strings."""
        if not self.root:
            return []

        func_def_query_str = '( function_definition ) @fd '
        func_def_query = self.tree_sitter_lang.query(func_def_query_str)

        function_res = func_def_query.captures(self.root)
        for _, funcs in function_res.items():
            for func in funcs:
                function_name = ''
                name_node = func
                while name_node.child_by_field_name('declarator') is not None:
                    name_node = name_node.child_by_field_name('declarator')
                    # Assign function name here because we want to make sure that there is a
                    # declarator when defining the name.
                    function_name = name_node.text.decode()

                if not function_name:
                    continue
                self.function_names.append(function_name)

    def get_function_node(self, target_function_name):
        """Gets the tree-sitter node corresponding to a function."""
        func_def_query_str = '( function_definition ) @fd '
        func_def_query = self.tree_sitter_lang.query(func_def_query_str)

        function_res = func_def_query.captures(self.root)
        for _, funcs in function_res.items():
            for func in funcs:
                function_name = ''
                name_node = func
                while name_node.child_by_field_name('declarator') is not None:
                    name_node = name_node.child_by_field_name('declarator')
                    # Assign function name here because we want to make sure that there is a
                    # declarator when defining the name.
                    function_name = name_node.text.decode()
                    if function_name == target_function_name:
                        return func
        return None

    def get_function_return_type(self, target_function_name):
        """Gets a function's return type as a string"""
        func = self.get_function_node(target_function_name)
        if not func:
            return ''

        ret_type = parameters_node = func.child_by_field_name(
            'type').text.decode()

        tmp_decl = func
        while tmp_decl.child_by_field_name(
                'declarator').type == 'pointer_declarator':
            ret_type += '*'
            tmp_decl = tmp_decl.child_by_field_name('declarator')

        return ret_type

    def get_function_arg_types(self, target_function_name):
        """Gets the text of a function's types"""
        param_types = []
        func = self.get_function_node(target_function_name)
        if not func:
            return param_types

        try:
            parameters_node = func.child_by_field_name(
                'declarator').child_by_field_name('parameters')
        except:
            return param_types

        if not parameters_node:
            return param_types

        for param in parameters_node.children:
            if not param.is_named:
                continue
            try:
                type_str = param.child_by_field_name('type').text.decode()

                param_tmp = param
                while param_tmp.child_by_field_name('declarator') is not None:
                    if param_tmp.type == 'pointer_declarator':
                        type_str += '*'
                    param_tmp = param_tmp.child_by_field_name('declarator')

                param_types.append(type_str)
            except:
                pass

        return param_types

    def get_function_arg_names(self, target_function_name):
        """Gets the same of a function's arguments"""
        param_names = []
        func = self.get_function_node(target_function_name)
        if not func:
            return param_names

        try:
            parameters_node = func.child_by_field_name(
                'declarator').child_by_field_name('parameters')
        except:
            return param_names

        if not parameters_node:
            return param_names

        for param in parameters_node.children:
            if not param.is_named:
                continue
            try:
                param_tmp = param
                while param_tmp.child_by_field_name('declarator') is not None:
                    param_tmp = param_tmp.child_by_field_name('declarator')
                param_names.append(param_tmp.text.decode())
            except:
                pass

        return param_names

    def function_signature(self, target_function_name):
        """Returns the function signature of a function as a string."""

        func = self.get_function_node(target_function_name)
        if not func:
            return ''

        function_signature = ''
        for child_idx in range(len(func.children)):
            child = func.child(child_idx)
            if child.is_named:
                if func.field_name_for_child(child_idx) == 'body':
                    break
            # TODO(David): fix decoding issue
            try:
                function_signature += child.text.decode() + ' '
            except:
                pass
        function_signature = function_signature.replace('\n',
                                                        '').replace('\\n', '')
        while '  ' in function_signature:
            function_signature = function_signature.replace('  ', ' ')
        return function_signature

    def has_libfuzzer_harness(self) -> bool:
        """Returns whether the source code holds a libfuzzer harness"""
        for func in self.function_names:
            if 'LLVMFuzzerTestOneInput' in func:
                return True
        return False

    def has_function_definition(self, target_function_name):
        """Returns if the source file holds a given function definition."""
        if target_function_name in self.function_names:
            return True

    def get_function_linenumber(self, target_function_name):
        """Gets the source file position of a given file."""
        func = self.get_function_node(target_function_name)
        if not func:
            return -1, -1
        start_pos = self.get_linenumber(func.byte_range[0])
        end_pos = self.get_linenumber(func.byte_range[1])
        return start_pos, end_pos

    def get_function_complexity(self, target_function_name):
        """Gets complexity measure based on counting branch nodes in a
        function."""
        func = self.get_function_node(target_function_name)
        if not func:
            return -1
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

        return _traverse_node_complexity(func)

    def get_function_instr_count(self, target_function_name):
        """Returns a pseudo measurement of instruction count."""
        func = self.get_function_node(target_function_name)
        if not func:
            return -1
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

        return _traverse_node_instr_count(func)

    def get_linenumber(self, bytepos):
        """Gets the line number corresponding to a byte range."""

        # TODO(David): fix up encoding issues.
        if not self.line_range_pairs:
            with open(self.source_file, 'r', encoding='utf-8') as f:
                try:
                    source_content = f.read()
                except:
                    # Set a value to avoid reading again.
                    self.line_range_pairs.append((-1, -1))
                    return -1

            payload_range = 0
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

    def get_callsites_in_function(self, target_function_name):
        """Gets the list of call sites in a function, as nodes in the
        treesitter tree."""
        callsites = []
        if not target_function_name in self.function_names:
            print('Did not find the function')
            return callsites

        call_query = self.tree_sitter_lang.query('( call_expression ) @ce')
        func_def_query_str = '( function_definition ) @fd '
        func_def_query = self.tree_sitter_lang.query(func_def_query_str)

        function_res = func_def_query.captures(self.root)
        for _, funcs in function_res.items():
            for func in funcs:
                function_name = ''
                name_node = func
                while name_node.child_by_field_name('declarator') is not None:
                    name_node = name_node.child_by_field_name('declarator')
                    # Assign function name here because we want to make sure that there is a
                    # declarator when defining the name.
                    function_name = name_node.text.decode()

                if function_name == target_function_name:
                    call_res = call_query.captures(func)

                    for _, call_exprs in call_res.items():
                        for call_expr in call_exprs:
                            # print('Call res')
                            for call_child in call_expr.children:

                                if call_child.type == 'identifier':
                                    callsites.append((call_child.text.decode(),
                                                      call_child.byte_range))

        # Sort the callsites relative to their end position. End position
        # here makes sense to handle cases of e.g.
        # func1(func2(), func3())
        # where the execution ordering is func2 -> func3 -> func1
        callsites = list(sorted(callsites, key=lambda x: x[1][1]))
        return callsites


def capture_source_files_in_tree(directory_tree, language):
    """Captures source code files in a given directory."""
    language_extensions = {'c': ['.c', '.h']}
    language_files = []
    for dirpath, _dirnames, filenames in os.walk(directory_tree):
        for filename in filenames:
            for extensions in language_extensions[language]:
                if pathlib.Path(filename).suffix in extensions:
                    language_files.append(os.path.join(dirpath, filename))
    return language_files


def load_treesitter_trees(source_files):
    """Creates treesitter trees for all files in a given list of source files."""
    results = []

    for language in source_files:
        if language == 'c':
            for code_file in source_files[language]:
                source_cls = SourceCodeFile(code_file, language)
                source_cls.get_defined_function_names()
                if source_cls.has_libfuzzer_harness():
                    print(code_file)
                results.append(source_cls)
    return results


def main():
    """Main"""
    source_files = {}
    source_files['c'] = capture_source_files_in_tree(sys.argv[1], 'c')
    source_codes = load_treesitter_trees(source_files)

    project = Project(source_codes)

    project.dump_module_logic('report.yaml')

    harnesses = []
    for idx, harness in enumerate(project.get_source_codes_with_harnesses()):
        print(f'Extracting calltree for {harness.source_file}')
        calltree = project.extract_calltree(harness, 'LLVMFuzzerTestOneInput')
        harnesses.append({'calltree': calltree})
        #print('-'*65)
        #print(calltree)
        #print('-'*65)
        #sys.exit(0)
        with open(f'fuzzer-calltree-{idx}', 'w', encoding='utf-8') as f:
            f.write(calltree)

    for idx, harness_dict in enumerate(harnesses):
        with open('fuzzer-calltree-%d' % (idx), 'w', encoding='utf-8') as f:
            f.write(harness_dict['calltree'])


if __name__ == "__main__":
    main()
