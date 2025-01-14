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
        self.uses: dict[str, str] = {}

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
        self._set_function_method_declaration(self.root)

    def load_tree(self):
        """Load the the source code into a treesitter tree, and set
        the root node."""
        self.root = self.parser.parse(self.source_content).root_node

    def _set_function_method_declaration(self,
                                         start_object: Node,
                                         start_prefix: list[str] = []):
        """Internal helper for retrieving all classes."""
        for node in start_object.children:
            # Reset prefix
            prefix = start_prefix[:]

            # Handle general functions
            if node.type == 'function_item':
                self.functions.append(
                    RustFunction(node, self.tree_sitter_lang, self, prefix))

            # Handle impl methods
            elif node.type == 'impl_item':
                # Basic info of this impl
                impl_type = node.child_by_field_name('type')
                impl_body = node.child_by_field_name('body')
                if impl_type:
                    prefix.append(impl_type.text.decode().split('<')[0])

                # Loop through the items in this impl
                for impl in impl_body.children:
                    # Handle general methods in this impl
                    if impl.type == 'function_item':
                        self.functions.append(
                            RustFunction(impl, self.tree_sitter_lang, self,
                                         prefix))

                    # Handles inner impl
                    elif impl.type == 'impl_item':
                        self._set_function_method_declaration(impl, prefix)

            # Handle mod functions
            elif node.type == 'mod_item':
                mod_body = node.child_by_field_name('body')
                if mod_body:
                    # Basic info of this mod
                    mod_name = node.child_by_field_name('name')
                    if mod_name:
                        prefix.append(mod_name.text.decode())

                    # Loop through the body of this mod
                    for mod in mod_body.children:
                        # Handle general function in this mod
                        if mod.type == 'function_item':
                            self.functions.append(
                                RustFunction(mod, self.tree_sitter_lang, self,
                                             prefix))

                        # Handles inner impl
                        elif mod.type == 'impl_item':
                            self._set_function_method_declaration(mod, prefix)

                        # Handles inner mod
                        elif mod.type == 'mod_item':
                            inner_body = mod.child_by_field_name('body')
                            if inner_body:
                                self._set_function_method_declaration(
                                    inner_body, prefix)

            # Handling trait item
            elif node.type == 'trait_item':
                # Basic info of this trait
                trait_name = node.child_by_field_name('name')
                trait_body = node.child_by_field_name('body')
                if trait_name:
                    prefix.append(trait_name.text.decode().split('<')[0])

                # Loop through the items in this trait
                for trait in trait_body.children:
                    # Handle general methods in this trait
                    if trait.type == 'function_item':
                        self.functions.append(
                            RustFunction(trait, self.tree_sitter_lang, self,
                                         prefix))

            # Handling for fuzzing harness entry point macro invocation
            elif node.type == 'expression_statement':
                for macro in node.children:
                    if macro.type == 'macro_invocation':
                        rust_function = RustFunction(macro,
                                                     self.tree_sitter_lang,
                                                     self,
                                                     prefix,
                                                     is_macro=True)

                        # Only consider the macro as function if it is the
                        # fuzzing entry point (fuzz_target macro)
                        if rust_function.is_entry_method:
                            self.functions.append(rust_function)

            # Handling specific use declaration
            elif node.type == 'use_declaration':
                use_stmt = node.child_by_field_name('argument')
                if use_stmt:
                    use_map = self._process_recursive_use(
                        use_stmt.text.decode())
                    self.uses.update(use_map)

            # Handling macro definition
            elif node.type == 'macro_definition':
                rust_function = RustFunction(node,
                                             self.tree_sitter_lang,
                                             self,
                                             prefix,
                                             is_macro=True)
                self.functions.append(rust_function)
            # TODO handle static_item / const_item

    def _split_use_stmt(self, use_stmt: str) -> list[str]:
        """Internal helper for spliting use statement with nested structure."""
        result = []
        current: list[str] = []
        brace_count = 0
        for char in use_stmt:
            if char == ',' and brace_count == 0:
                result.append(''.join(current))
                current = []
            else:
                current.append(char)
                if char == '{':
                    brace_count += 1
                elif char == '}':
                    brace_count -= 1

        if current:
            result.append(''.join(current))

        return result

    def _process_recursive_use(self,
                               use_stmt: str,
                               path: str = '') -> dict[str, str]:
        """Internal recursive function to process use statement."""
        result = {}

        use_stmt = use_stmt.replace(' ', '').removeprefix('crate::')
        prefix, *suffix = use_stmt.split('::{', 1)
        if suffix:
            inner = suffix[0]
            if inner.endswith('}'):
                inner = inner[:-1]
            for item in self._split_use_stmt(inner):
                result.update(
                    self._process_recursive_use(item, f'{path}{prefix}::'))
        else:
            name = prefix.split('::')[-1]
            result[name] = f'{path}{prefix}'

        return result

    def has_libfuzzer_harness(self) -> bool:
        """Returns whether the source code holds a libfuzzer harness"""
        if any(func.is_entry_method for func in self.functions):
            return True

        return False

    def get_entry_function(self) -> Optional['RustFunction']:
        """Returns the entry function of the harness if found."""
        if self.has_libfuzzer_harness():
            for func in self.functions:
                if func.is_entry_method:
                    return func

        return None


class RustFunction():
    """Wrapper for a General Declaration for function"""

    def __init__(self,
                 root: Node,
                 tree_sitter_lang: Language,
                 source_code: SourceCodeFile,
                 prefix: list[str],
                 is_macro: bool = False):
        self.root = root
        self.tree_sitter_lang = tree_sitter_lang
        self.parent_source = source_code
        self.prefix = prefix
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
        self.stmts: list[Node] = []
        self.fuzzing_token_tree = None
        self.var_map: dict[str, str] = {}

        # Process method declaration
        if is_macro:
            self._process_macro_declaration()
        else:
            self._process_declaration()

        # Process variable declaration
        self._process_variables()

        # Process complexity
        self._process_complexity()

        # Process instr count
        self._process_icount()

    def _process_declaration(self):
        """Internal helper to process the function/method declaration."""
        # Process name
        self.name = self.root.child_by_field_name('name').text.decode()
        if self.prefix:
            self.name = f'{"::".join(self.prefix)}::{self.name}'

        # Process return type
        return_type = self.root.child_by_field_name('return_type')
        if return_type:
            self.return_type = return_type.text.decode().split('<')[0]
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
        self.sig = ''.join(line.strip() for line in signature.splitlines()
                           if line.strip())

        # Process body
        body = self.root.child_by_field_name('body')
        if body:
            for stmt in body.children:
                if 'expression' in stmt.type or 'declaration' in stmt.type:
                    self.stmts.append(stmt)
                elif stmt.type == 'function_item':
                    # Handle inner function:
                    self.parent_source.functions.append(
                        RustFunction(stmt, self.tree_sitter_lang,
                                     self.parent_source, self.name))

    def _process_macro_declaration(self):
        """Internal helper to process the macro declaration for fuzzing
        entry point."""
        for child in self.root.children:
            # Process name
            if child.type == 'identifier':
                self.name = child.text.decode()
                if self.name == 'fuzz_target':
                    self.is_entry_method = True

            # Store token tree
            elif child.type == 'token_tree':
                for token_tree in child.children:
                    if token_tree.type == 'token_tree':
                        content = token_tree.text.decode()
                        if content.startswith('{'):
                            bytes = content.encode('utf-8')
                            root = self.parent_source.parser.parse(bytes)
                            self.fuzzing_token_tree = root.root_node

            elif child.type == 'macro_rule':
                token_tree = child.child_by_field_name('right')
                if token_tree:
                    content = token_tree.text.decode()
                    if content.startswith('{'):
                        bytes = content.encode('utf-8')
                        root = self.parent_source.parser.parse(bytes)
                        self.fuzzing_token_tree = root.root_node

    def _process_variables(self):
        """Process variable declaration and store them for reference."""
        # Parameters
        for arg_name, arg_type in zip(self.arg_names, self.arg_types):
            self.var_map[arg_name] = arg_type

    def _process_complexity(self):
        """Gets complexity measure based on counting branch nodes in a
        function."""

        branch_nodes = [
            'if_expression',
            'match_expression',
            'while_expression',
            'loop_expression',
            'for_expression',
            'try_expression',
            'try_block',
            'async_block',
            'await_expression',
            'unsafe_block',
            'gen_block',
            'break_expression',
            'continue_expression',
            '&&',
            '||',
        ]

        def _traverse_node_complexity(node: Node):
            count = 0
            if node.type in branch_nodes:
                count += 1
            for item in node.children:
                count += _traverse_node_complexity(item)
            return count

        if self.fuzzing_token_tree:
            self.complexity += _traverse_node_complexity(
                self.fuzzing_token_tree)
        else:
            self.complexity += _traverse_node_complexity(self.root)

    def _process_icount(self):
        """Get a pseudo measurement of instruction count."""

        def _traverse_node_instr_count(node: Node) -> int:
            count = 0
            if 'expression' in node.type:
                count += 1
            for item in node.children:
                count += _traverse_node_instr_count(item)
            return count

        if self.fuzzing_token_tree:
            self.icount += _traverse_node_instr_count(self.fuzzing_token_tree)
        else:
            self.icount += _traverse_node_instr_count(self.root)

    def extract_callsites(self, functions: dict[str, 'RustFunction']):
        """Extract callsites."""

        def _process_invoke(expr: Node) -> list[tuple[str, int, int]]:
            """Internal helper for processing the function invocation statement."""
            callsites = []
            target_name: str = ''

            func = expr.child_by_field_name('function')

            # Handle function call
            if func:
                # Simple function call
                if func.type in ['identifier', 'scoped_identifier']:
                    target_name = func.text.decode()

                    # Ignore lambda function calls
                    if target_name in self.var_map:
                        lambda_prefix = ('impl', 'fn', 'unsafe fn')
                        if self.var_map[target_name].startswith(lambda_prefix):
                            target_name = ''

                # Chained or instance function call
                elif func.type == 'field_expression':
                    _, target_name = _process_field_expr_return_type(func)

                elif func.type == 'generic_function':
                    target_name = func.text.decode().split('.', 1)[-1]

            if target_name:
                callsites.append((target_name, func.byte_range[1],
                                  func.start_point.row + 1))

            return callsites

        def _process_token_tree(
                token_tree: Node) -> list[tuple[str, int, int]]:
            """Process and store the callsites of token tree."""
            callsites = []

            for child in token_tree.children:
                callsites.extend(_process_callsites(child))

            return callsites

        def _process_field_expr_return_type(
                field_expr: Node) -> tuple[Optional[str], str]:
            """Helper for determining the return type of a field expression
            in a chained call and its full qualified name."""
            type = None

            name = field_expr.child_by_field_name('field').text.decode()
            object = field_expr.child_by_field_name('value')
            full_name = name

            object_type = None
            if object.type == 'call_expression':
                object_type = _retrieve_return_type(object)
            elif object.type in ['identifier', 'scoped_identifier']:
                object_text = object.text.decode()
                node = get_function_node(object_text, functions)
                if node:
                    object_type = node.return_type
                else:
                    object_type = self.var_map.get(object_text)
            elif object.type == 'self':
                object_type = self.name.rsplit('::', 1)[0]

            elif object.type == 'string_literal':
                object_type = '&str'

            if object_type:
                if object_type == 'void':
                    full_name = name
                else:
                    full_name = f'{object_type}::{name}'

                node = get_function_node(full_name, functions)
                if node:
                    type = node.return_type

            return ((type, full_name))

        def _retrieve_return_type(call_expr: Node) -> Optional[str]:
            """Helper for determining the return type of a call expression."""
            type = None

            func = call_expr.child_by_field_name('function')
            if func:
                if func.type in ['identifier', 'scoped_identifier']:
                    func_name = func.text.decode()
                    node = get_function_node(func_name, functions)
                    if node:
                        type = node.return_type
                elif func.type == 'field_expression':
                    type, _ = _process_field_expr_return_type(func)

            return type

        def _process_callsites(stmt: Node) -> list[tuple[str, int, int]]:
            """Process and store the callsites of the function."""
            callsites = []
            if stmt.type == 'call_expression':
                callsites.extend(_process_invoke(stmt))

            elif stmt.type == 'let_declaration':
                param_name = stmt.child_by_field_name('pattern')
                param_type = stmt.child_by_field_name('value')
                if param_name and param_type:
                    name = param_name.text.decode()
                    type = None
                    if param_type.type == 'identifier':
                        target = param_type.text.decode()
                        type = self.var_map.get(target)
                        if not type:
                            type = self.parent_source.uses.get(target)
                        if not type:
                            type = target
                    elif param_type.type == 'type_cast_expression':
                        # In general, type casted object are not callable
                        # This exists for type safety in case variable tracing for
                        # pointers and primitive types are needed.
                        type = param_type.child_by_field_name(
                            'type').text.decode()
                    elif param_type.type == 'call_expression':
                        type = _retrieve_return_type(param_type)
                    elif param_type.type == 'reference_expression':
                        for ref_type in param_type.children:
                            if ref_type.type == 'identifier':
                                type = self.var_map.get(ref_type.text.decode())
                            elif ref_type.type == 'call_expression':
                                type = _retrieve_return_type(ref_type)

                    if type:
                        self.var_map[name] = type

            elif stmt.type == 'macro_invocation':
                for child in stmt.children:
                    if child.type == 'identifier':
                        macro_name = child.text.decode()
                        target_func = get_function_node(macro_name, functions)
                        if target_func and target_func.is_macro:
                            callsites.append(
                                (target_func.name, stmt.byte_range[1],
                                 stmt.start_point.row + 1))

            for child in stmt.children:
                callsites.extend(_process_callsites(child))

            return callsites

        if not self.base_callsites:
            callsites = []
            if self.fuzzing_token_tree:
                callsites.extend(_process_token_tree(self.fuzzing_token_tree))
            else:
                for stmt in self.stmts:
                    callsites.extend(_process_callsites(stmt))
            callsites = sorted(set(callsites), key=lambda x: x[1])

            # Post process callsites with use statement
            processed_callsites = []
            for item in callsites:
                crate_name = self.parent_source.uses.get(item[0], item[0])
                new_item = (crate_name, item[1], item[2])
                processed_callsites.append(new_item)

            self.base_callsites = [(x[0], x[2]) for x in processed_callsites]

        if not self.detailed_callsites:
            for dst, src_line in self.base_callsites:
                src_loc = self.parent_source.source_file + ':%d,1' % (src_line)
                self.detailed_callsites.append({'Src': src_loc, 'Dst': dst})


class Project():
    """Wrapper for doing analysis of a collection of source files."""

    def __init__(self, source_code_files: list[SourceCodeFile]):
        self.source_code_files = source_code_files

    def dump_module_logic(self,
                          report_name: str,
                          harness_name: Optional[str] = None,
                          harness_source: str = ''):
        """Dumps the data for the module in full."""
        logger.info('Dumping project-wide logic.')
        report: dict[str, Any] = {'report': 'name'}
        report['sources'] = []
        report['Fuzzer filename'] = harness_source

        self.all_functions = {}
        for source_code in self.source_code_files:
            # Log entry method if provided
            entry_method = source_code.get_entry_function()
            if entry_method:
                report['Fuzzing method'] = entry_method.name

            # Retrieve project information
            func_names = [func.name for func in source_code.functions]
            report['sources'].append({
                'source_file': source_code.source_file,
                'function_names': func_names,
            })

            # Obtain all functions of the project
            source_code_functions = {
                func.name: func
                for func in source_code.functions
            }

            # Process entry method
            if source_code.has_libfuzzer_harness():
                if f'{harness_name}.rs' not in source_code.source_file:
                    del source_code_functions['fuzz_target']

            self.all_functions.update(source_code_functions)

        # Process all project functions
        func_list = []
        for func in self.all_functions.values():
            func.extract_callsites(self.all_functions)

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
            func_dict['functionUses'] = self.calculate_function_uses(
                func.name, list(self.all_functions.values()))
            func_dict['functionDepth'] = self.calculate_function_depth(
                func, self.all_functions)
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

    def _find_source_with_function(self,
                                   name: str) -> Optional[SourceCodeFile]:
        """Finds the source code with a given function name."""
        for source_code in self.source_code_files:
            if get_function_node(
                    name, {func.name: func
                           for func in source_code.functions}):
                return source_code

        return None

    def calculate_function_uses(self, target_name: str,
                                all_functions: list[RustFunction]) -> int:
        """Calculate how many functions called the target function."""
        func_use_count = 0
        for function in all_functions:
            found = False
            for callsite in function.base_callsites:
                if callsite[0] == target_name:
                    found = True
                    break
                elif callsite[0].endswith(target_name):
                    found = True
                    break
            if found:
                func_use_count += 1

        return func_use_count

    def calculate_function_depth(
            self, target_function: RustFunction,
            all_functions: dict[str, RustFunction]) -> int:
        """Calculate function depth of the target function."""

        def _recursive_function_depth(function: RustFunction) -> int:
            callsites = function.base_callsites
            if len(callsites) == 0:
                return 0

            depth = 0
            visited.append(function.name)
            for callsite in callsites:
                target = get_function_node(callsite[0], all_functions, True)
                if target and target.name in visited:
                    depth = max(depth, 1)
                elif target:
                    depth = max(depth, _recursive_function_depth(target) + 1)
                else:
                    visited.append(callsite[0])

            return depth

        visited: list[str] = []
        func_depth = _recursive_function_depth(target_function)

        return func_depth

    def extract_calltree(self,
                         source_file: str,
                         source_code: Optional[SourceCodeFile] = None,
                         func: Optional[str] = None,
                         visited_funcs: Optional[set[str]] = None,
                         depth: int = 0,
                         line_number: int = -1,
                         is_macro: bool = False) -> str:
        """Extracts calltree string of a calltree so that FI core can use it."""
        func_node = None

        if not visited_funcs:
            visited_funcs = set()

        if not source_code and func:
            source_code = self._find_source_with_function(func)

        if not func and source_code:
            func_node = source_code.get_entry_function()
            if func_node:
                func = func_node.name

        if func:
            if not func_node:
                func_node = get_function_node(func, self.all_functions)

            if func_node and not is_macro:
                func_name = func_node.name
                if func.count('::') > func_name.count('::'):
                    func_name = func
            else:
                func_node = None
                func_name = func
        else:
            return ''

        line_to_print = '  ' * depth
        line_to_print += func_name
        line_to_print += ' '
        line_to_print += source_file

        line_to_print += ' '
        line_to_print += str(line_number)

        line_to_print += '\n'

        if func in visited_funcs or not func_node or not source_code or not func:
            return line_to_print

        callsites = func_node.base_callsites
        visited_funcs.add(func)

        for cs, line_number in callsites:
            is_macro = bool(func_node and func_node.is_macro
                            and func_node.name != 'fuzz_target')
            line_to_print += self.extract_calltree(source_code.source_file,
                                                   func=cs,
                                                   visited_funcs=visited_funcs,
                                                   depth=depth + 1,
                                                   line_number=line_number,
                                                   is_macro=is_macro)

        return line_to_print

    def get_source_codes_with_harnesses(self) -> list[SourceCodeFile]:
        """Gets the source codes that holds libfuzzer harnesses."""
        harnesses = []
        for source_code in self.source_code_files:
            if source_code.has_libfuzzer_harness():
                harnesses.append(source_code)

        return harnesses

    def get_reachable_functions(
            self,
            source_file: str,
            source_code: Optional[SourceCodeFile] = None,
            func: Optional[str] = None,
            visited_funcs: Optional[set[str]] = None) -> set[str]:
        """Get a list of reachable functions for a provided function name."""
        func_node = None

        if not visited_funcs:
            visited_funcs = set()

        if not source_code and func:
            source_code = self._find_source_with_function(func)

        if not func and source_code:
            func_node = source_code.get_entry_function()
            if func_node:
                func = func_node.name

        if source_code and func:
            if not func_node:
                func_node = get_function_node(func, self.all_functions)

            if not func_node:
                visited_funcs.add(func)
                return visited_funcs
        else:
            if func:
                visited_funcs.add(func)
            return visited_funcs

        visited_funcs.add(func)
        for cs, _ in func_node.base_callsites:
            if cs in visited_funcs:
                continue

            visited_funcs = self.get_reachable_functions(
                source_code.source_file, func=cs, visited_funcs=visited_funcs)

        return visited_funcs


def capture_source_files_in_tree(directory_tree: str) -> list[str]:
    """Captures source code files in a given directory."""
    exclude_directories = [
        'tests', 'examples', 'benches', 'node_modules', 'aflplusplus',
        'honggfuzz', 'inspector', 'libfuzzer'
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


def get_function_node(target_name: str,
                      function_map: dict[str, RustFunction],
                      one_layer_only: bool = False) -> Optional[RustFunction]:
    """Helper to retrieve the RustFunction object of a function."""

    # Exact match
    if target_name in function_map:
        return function_map[target_name]

    # Match any key that ends with target_name, then
    # split the target_name by :: and check one by one
    if one_layer_only:
        name_split = target_name.split('::', 1)
    else:
        name_split = target_name.split('::')
    for count in range(len(name_split)):
        for func_name, func in function_map.items():
            if func_name.endswith('::'.join(name_split[count:])):
                return func

    return None
