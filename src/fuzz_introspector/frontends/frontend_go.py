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

LITERAL_TYPE_MAP = {
    "_string_literal": "string",
    "int_literal": "int",
    "float_literal": "float64",
    "imaginary_literal": "complex128",
    "rune_literal": "rune",
    "true": "bool",
    "false": "bool",
    "iota": "int"
}


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
            func_names.append(func.function_name)
        for method in self.methods:
            func_names.append(method.function_name)
        return func_names

    def get_function_node(
            self, target_function_name: str) -> Optional['FunctionMethod']:
        """Gets the tree-sitter node corresponding to a function."""

        # Find the first instance of the function name
        for func in self.functions:
            if func.function_name == target_function_name:
                return func

        for method in self.methods:
            if method.function_name == target_function_name:
                return method

        return None

    def has_libfuzzer_harness(self) -> bool:
        """Returns whether the source code holds a libfuzzer harness"""
        if any(
                func.function_name.startswith('Fuzz')
                for func in self.functions):
            return True

        if any(meth.function_name.startswith('Fuzz') for meth in self.methods):
            return True

        return False

    def has_function_definition(self, target_function_name: str) -> bool:
        """Returns if the source file holds a given function definition."""

        if any(func.function_name == target_function_name
               for func in self.functions):
            return True

        if any(meth.function_name == target_function_name
               for meth in self.methods):
            return True

        return False

    def get_entry_function_name(self) -> str:
        """Returns the entry function name of the harness if found,"""
        for func in (self.functions + self.methods):
            if func.function_name.startswith('Fuzz'):
                return func.function_name

        return ''


class Project():
    """Wrapper for doing analysis of a collection of source files."""

    def __init__(self, source_code_files: list[SourceCodeFile]):
        self.source_code_files = source_code_files
        full_functions_methods = [
            item for src in source_code_files
            for item in src.functions + src.methods
        ]
        self.functions_methods_map = {
            item.function_name: item
            for item in full_functions_methods
        }

    def dump_module_logic(self,
                          report_name: str,
                          entry_function: str = '',
                          harness_source: str = ''):
        """Dumps the data for the module in full."""
        logger.info('Dumping project-wide logic.')
        report: dict[str, Any] = {'report': 'name'}
        report['sources'] = []
        report['Fuzzer filename'] = harness_source

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
                func_def.extract_local_variable_type(
                    self.functions_methods_map)
                # Need a second pass because the processing may out of order
                # That could affect some local variable types that are
                # relying on other variables
                func_def.extract_local_variable_type(
                    self.functions_methods_map)

                func_def.extract_callsites(self.functions_methods_map)
                func_dict: dict[str, Any] = {}
                func_dict['functionName'] = func_def.function_name
                func_dict['functionSourceFile'] = source_code.source_file
                func_dict['functionLinenumber'] = func_def.start_line
                func_dict['functionLinenumberEnd'] = func_def.end_line
                func_dict['linkageType'] = ''
                func_dict['func_position'] = {
                    'start': func_def.start_line,
                    'end': func_def.end_line
                }
                func_dict['CyclomaticComplexity'] = func_def.complexity
                func_dict['EdgeCount'] = func_dict['CyclomaticComplexity']
                func_dict['ICount'] = func_def.icount
                func_dict['argNames'] = func_def.arg_names[:]
                func_dict['argTypes'] = func_def.arg_types[:]
                func_dict['argCount'] = len(func_dict['argTypes'])
                func_dict['returnType'] = func_def.return_type
                func_dict['BranchProfiles'] = []
                func_dict['Callsites'] = func_def.detailed_callsites
                func_dict['functionUses'] = func_def.get_function_uses(
                    list(self.functions_methods_map.values()))
                func_dict['functionDepth'] = func_def.get_function_depth(
                    list(self.functions_methods_map.values()))
                func_dict['constantsTouched'] = []
                func_dict['BBCount'] = 0
                func_dict['signature'] = func_def.sig
                func_callsites = func_def.base_callsites
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

        if function in visited_functions:
            return line_to_print

        visited_functions.add(function)
        for cs, line_number in func.base_callsites:
            line_to_print += self.extract_calltree(
                source_code.source_file,
                function=cs,
                visited_functions=visited_functions,
                depth=depth + 1,
                line_number=line_number)
        return line_to_print

    def get_reachable_functions(
            self,
            source_file: str,
            source_code: Optional[SourceCodeFile] = None,
            function: Optional[str] = None,
            visited_functions: Optional[set[str]] = None) -> set[str]:
        """Get a list of reachable functions for a provided function name."""
        if not visited_functions:
            visited_functions = set()

        if not function and source_code:
            function = source_code.get_entry_function_name()

        if not function:
            return visited_functions

        if not source_code and function:
            source_code = self.find_source_with_func_def(function)

        if not source_code:
            visited_functions.add(function)
            return visited_functions

        func = source_code.get_function_node(function)
        if not func or function in visited_functions:
            visited_functions.add(function)
            return visited_functions

        visited_functions.add(function)
        for cs, line_number in func.base_callsites:
            visited_functions = self.get_reachable_functions(
                source_code.source_file,
                function=cs,
                visited_functions=visited_functions)

        return visited_functions

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
        self.receiver = ''
        self.receiver_name = ''
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
        self.var_map: dict[str, str] = {}

        # Process properties
        self._process_properties()

        # Process complexity
        self._process_complexity()

        # Process icount
        self._process_icount()

    def get_function_uses(self,
                          all_funcs_meths: list['FunctionMethod']) -> int:
        """Calculate how many function called this function."""
        if not self.function_uses:
            for func in all_funcs_meths:
                found = False
                for callsite in func.base_callsites:
                    if callsite[0] == self.function_name:
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
        func_meth_dict = {f.function_name: f for f in all_funcs_meths}

        def _recursive_function_depth(func_meth: FunctionMethod) -> int:
            callsites = func_meth.base_callsites
            if len(callsites) == 0:
                return 0

            visited.append(func_meth.function_name)
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

    def _process_properties(self):
        """Process properties."""

        # Process receiver
        receiver = self.root.child_by_field_name('receiver')
        if receiver:
            for child in receiver.children:
                if child.type == 'parameter_declaration':
                    receiver_name = child.child_by_field_name('name')
                    receiver_type = child.child_by_field_name('type')

                    if receiver_name and receiver_type:
                        self.receiver = receiver_type.text.decode()
                        self.receiver_name = receiver_name.text.decode()
                        self.var_map[self.receiver_name] = self.receiver

        # Process name
        name_node = self.root
        while name_node.child_by_field_name('name') is not None:
            name_node = name_node.child_by_field_name('name')
            self.function_name = name_node.text.decode()
        if self.receiver:
            self.function_name = f'{self.receiver}.{self.function_name}'

        # Process arguments
        param_names = []
        param_types = []
        query = self.tree_sitter_lang.query('( parameter_list ) @pl')
        for _, exprs in query.captures(self.root).items():
            for param_node in exprs:
                for param in param_node.children:
                    if not param.is_named:
                        continue

                    param_name = ''
                    param_type = ''

                    # Param name
                    param_tmp = param
                    while param_tmp.child_by_field_name('name') is not None:
                        param_tmp = param_tmp.child_by_field_name('name')
                    param_name = param_tmp.text.decode()

                    # Param type
                    if param.child_by_field_name('type'):
                        type_str = param.child_by_field_name(
                            'type').text.decode()
                        param_tmp = param
                        while param_tmp.child_by_field_name(
                                'declarator') is not None:
                            if param_tmp.type == 'pointer_declarator':
                                type_str += '*'
                            param_tmp = param_tmp.child_by_field_name(
                                'declarator')
                        param_type = type_str

                    if param_name:
                        if param_name != self.receiver_name:
                            param_names.append(param_name)
                            param_types.append(param_type)
                            self.var_map[param_names[-1]] = param_types[-1]

        self.arg_names = param_names
        self.arg_types = param_types

        # Process return value
        result = self.root.child_by_field_name('result')
        if result:
            self.return_type = result.text.decode()
        else:
            self.return_type = 'void'

        # Process signature
        # Go function signature format
        # (Optional_Receiver) Func_Name(Argument_Types) Optional_Return_Type
        self.sig = f'{self.function_name}({",".join(self.arg_types)})'

        if self.return_type != 'void':
            self.sig = f'{self.sig} {self.return_type}'

        if self.receiver:
            self.sig = f'({self.receiver}) {self.sig}'

    def _process_complexity(self):
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

        self.complexity = _traverse_node_complexity(self.root)

    def _process_icount(self):
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

        self.icount = _traverse_node_instr_count(self.root)

    def _process_call_expr_child(
            self, call_child: Node,
            all_funcs_meths: dict[str, 'FunctionMethod']) -> Optional[str]:
        """Internal helper to process call expr."""
        target_name = None

        # Simple call
        if call_child.type == 'identifier':
            target_name = call_child.text.decode()

        # Package/method call
        if call_child.type == 'selector_expression':
            target_name = call_child.text.decode()
            # Variable call
            split_call = target_name.split('.')
            if len(split_call) > 1:
                # For indexing selector
                if '[' in split_call[-2] and ']' in split_call[-2]:
                    var_name = self.var_map.get(split_call[-2].split('[')[0])
                    if var_name:
                        if '[' in var_name and ']' in var_name:
                            var_name = var_name.split(']')[-1]
                        elif var_name == 'string':
                            var_name = 'uint8'
                else:
                    var_name = self.var_map.get(split_call[-2])
                if var_name:
                    target_name = f'{var_name}.{split_call[-1]}'

                elif split_call[0] not in self.parent_source.imports:
                    target_name = target_name.split('.')[-1]

            # Chain call
            split_call = target_name.rsplit(').', 1)
            if len(split_call) > 1:
                target_name = split_call[1]

        return target_name

    def _detect_variable_type(
            self, node: Node,
            all_funcs_meths: dict[str, 'FunctionMethod']) -> Optional[str]:
        """Internal recursive helper to determine the return type of the expression."""

        for child in node.children:
            # Literals
            if child.type in LITERAL_TYPE_MAP:
                return LITERAL_TYPE_MAP[child.type]

            # Identifier
            elif child.type == 'identifier':
                if child.text.decode() in self.var_map:
                    return self.var_map[child.text.decode()]

            # Composite Literal
            elif child.type == 'composite_literal':
                composite_type = child.child_by_field_name('type')
                if composite_type:
                    return composite_type.text.decode()

            # Call expression
            elif child.type == 'call_expression':
                call = child.child_by_field_name('function')
                args = child.child_by_field_name('arguments')
                target_name = self._process_call_expr_child(
                    call, all_funcs_meths)

                if target_name in all_funcs_meths:
                    return all_funcs_meths[target_name].return_type

                elif target_name == 'new':
                    for arg in args.children:
                        if arg.type.endswith('identifier'):
                            return arg.text.decode()

                elif target_name == 'make':
                    for arg in args.children:
                        type_node = arg.child_by_field_name('value')
                        if type_node:
                            return type_node.text.decode()

                        type_node = arg.child_by_field_name('element')
                        if type_node:
                            return type_node.text.decode()

            # Selector expression
            elif child.type == 'selector_expression':
                target_name = self._process_call_expr_child(
                    child, all_funcs_meths)
                if target_name:
                    return target_name

            # Index expression / Slice expression
            elif child.type in ['index_expression', 'slice_expression']:
                op = child.child_by_field_name('operand')
                parent_type = self.var_map.get(op.text.decode())
                if parent_type:
                    if '[' in parent_type and ']' in parent_type:
                        return parent_type.rsplit(']', 1)[-1]
                    elif parent_type == 'string':
                        return 'uint8'

            # Other expression that need to recursive deeper
            # unary_expression binary_expression
            # parenthesized_expression
            else:
                return self._detect_variable_type(child, all_funcs_meths)

        return None

    def extract_local_variable_type(self,
                                    all_funcs_meths: dict[str,
                                                          'FunctionMethod']):
        """Gets the local variable types of the function."""

        query = self.tree_sitter_lang.query('( short_var_declaration ) @vd')
        for _, exprs in query.captures(self.root).items():
            for decl_node in exprs:
                left = decl_node.child_by_field_name('left')
                right = decl_node.child_by_field_name('right')
                if not left or not right:
                    continue

                for child in left.children:
                    if child.type == 'identifier':
                        decl_name = child.text.decode()

                decl_type = self._detect_variable_type(right, all_funcs_meths)

                if decl_name and decl_type:
                    self.var_map[decl_name] = decl_type

        query = self.tree_sitter_lang.query('( for_statement ) @fd')
        for _, exprs in query.captures(self.root).items():
            for for_node in exprs:
                for child in for_node.children:
                    if child.type == 'range_clause':
                        left = child.child_by_field_name('left')
                        right = child.child_by_field_name('right')
                        if not left or not right:
                            continue

                        for left_child in left.children:
                            if left_child.type == 'identifier':
                                decl_name = left_child.text.decode()

                        if right.type == 'identifier':
                            decl_type = self.var_map.get(
                                right.text.decode(), '')
                            if '[' in decl_type and ']' in decl_type:
                                decl_type = decl_type.split(']', 1)[-1]
                            elif decl_type == 'string':
                                decl_type = 'uint8'
                        else:
                            decl_type = self._detect_variable_type(
                                right, all_funcs_meths)

                        if decl_name and decl_type:
                            self.var_map[decl_name] = decl_type

    def extract_callsites(self, all_funcs_meths: dict[str, 'FunctionMethod']):
        """Gets the callsites of the function."""

        callsites = []
        call_query = self.tree_sitter_lang.query('( call_expression ) @ce')
        call_res = call_query.captures(self.root)
        for _, call_exprs in call_res.items():
            for call_expr in call_exprs:
                call = call_expr.child_by_field_name('function')
                target_name = self._process_call_expr_child(
                    call, all_funcs_meths)
                if target_name in ['new', 'make']:
                    if target_name not in all_funcs_meths:
                        target_name = None

                if target_name:
                    callsites.append((
                        target_name,
                        call_expr.byte_range,
                        call_expr.start_point.row + 1,
                    ))

        callsites = sorted(callsites, key=lambda x: x[1][0])
        self.base_callsites = [(x[0], x[2]) for x in callsites]
        # Process detailed callsites
        for dst, src_line in self.base_callsites:
            src_loc = self.parent_source.source_file + ':%d,1' % (src_line)
            self.detailed_callsites.append({'Src': src_loc, 'Dst': dst})


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
