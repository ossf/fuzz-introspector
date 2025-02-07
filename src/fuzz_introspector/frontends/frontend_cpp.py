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
"""Tree-sitter frontend for cpp."""

from typing import Any, Optional

from tree_sitter import Language, Node

import os
import logging

from fuzz_introspector.frontends import datatypes

logger = logging.getLogger(name=__name__)


class CppSourceCodeFile(datatypes.SourceCodeFile):
    """Class for holding file-specific information."""

    def language_specific_process(self) -> None:
        """Function to perform some language specific processes in
        subclasses."""
        self.func_defs: list['FunctionDefinition'] = []
        if self.source_content:
            # Initialization routines
            self.load_tree()
            if self.root:
                self.process_tree(self.root)

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
                    if not child.is_named or not child.text:
                        continue
                    namespace += '::' + child.text.decode()
                    if namespace.startswith('::'):
                        namespace = namespace[2:]

            # General namespace
            elif new_namespace.type == 'namespace_identifier':
                if new_namespace.text:
                    namespace += '::' + new_namespace.text.decode()
                    if namespace.startswith('::'):
                        namespace = namespace[2:]

        # Continue to process the tree of the namespace
        self.process_tree(node, namespace)

    def _process_function_node(self, node: Node, namespace: str = ''):
        """Internal helper for processing function node."""

        self.func_defs.append(
            FunctionDefinition(node, self.tree_sitter_lang, self, namespace))

    def get_function_node(
            self,
            target_function_name: str,
            exact: bool = False) -> Optional['FunctionDefinition']:
        """Gets the tree-sitter node corresponding to a function."""

        # Find the first instance of the function name
        for func in self.func_defs:
            if func.namespace_or_class:
                check_name = func.namespace_or_class + '::' + func.name
                if check_name == target_function_name:
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

    def has_libfuzzer_harness(self) -> bool:
        """Returns whether the source code holds a libfuzzer harness"""
        for func in self.func_defs:
            if 'LLVMFuzzerTestOneInput' in func.name:
                return True

        return False


class FunctionDefinition():
    """Wrapper for a function definition"""

    def __init__(self, root: Node, tree_sitter_lang: Language,
                 source_code: CppSourceCodeFile, namespace: str):
        self.root = root
        self.tree_sitter_lang = tree_sitter_lang
        self.parent_source = source_code
        self.namespace_or_class = namespace

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
        self.var_map: dict[str, str] = {}
        self.depth = -1

        # Extract information from tree-sitter node
        self._extract_information()

    def function_source_code_as_text(self) -> str:
        """Returns the source code the function."""
        if self.root and self.root.text:
            return self.root.text.decode()

        return ''

    def _extract_pointer_array_from_type(
            self, param_name: Node) -> tuple[int, int, Node]:
        """Extract the pointer, array count from type and return the
        pain type."""
        # Count pointer
        pointer_count = 0
        while param_name.type == 'pointer_declarator':
            pointer_count += 1
            child = param_name.child_by_field_name('declarator')
            if child:
                param_name = child
            else:
                break

        # Count array
        array_count = 0
        while param_name.type == 'array_declarator':
            array_count += 1
            child = param_name.child_by_field_name('declarator')
            if child:
                param_name = child
            else:
                break

        return (pointer_count, array_count, param_name)

    def _extract_information(self):
        """Extract information from tree-sitter node."""
        # Extract function name and return type
        name_node = self.root.child_by_field_name('declarator')
        self.sig = name_node.text.decode()
        logger.debug('Extracting information for %s', self.sig)
        param_list_node = None
        for child in name_node.children:
            if 'identifier' in child.type:
                self.name = child.text.decode()

            elif child.type == 'function_declarator':
                for decl in child.children:
                    if 'identifier' in decl.type:
                        self.name = decl.text.decode()

                    elif decl.type == 'parameter_list':
                        param_list_node = decl

            elif child.type == 'parameter_list':
                param_list_node = child

        # Handle the full name
        # Extract the scope that the function is defined in
        logger.debug('Iterating parents')
        tmp_root = self.root
        full_name = ''
        while True:
            logger.debug('step')
            new_parent = tmp_root.parent
            if new_parent is None:
                break
            if (new_parent.type == 'class_specifier'
                    and new_parent.child_by_field_name('name') is not None):
                full_name = new_parent.child_by_field_name(
                    'name').text.decode() + '::' + full_name
            if new_parent.type == 'namespace_definition':
                # Ignore anonymous namespaces
                if new_parent.child_by_field_name('name') is not None:
                    full_name = new_parent.child_by_field_name(
                        'name').text.decode() + '::' + full_name
            tmp_root = new_parent
        logger.debug('Full function scope not from name: %s', full_name)

        # Extract the name from the function declarator
        tmp_name = ''
        tmp_node = self.root.child_by_field_name('declarator')
        scope_to_add = ''
        while True:
            if tmp_node is None:
                break
            if tmp_node.type == 'reference_declarator':
                for child in tmp_node.children:
                    if child.type == 'function_declarator':
                        if child.child_by_field_name(
                                'declarator').type == 'identifier':
                            tmp_name = child.child_by_field_name(
                                'declarator').text.decode()
            if tmp_node.child_by_field_name('scope') is not None:
                scope_to_add = tmp_node.child_by_field_name(
                    'scope').text.decode() + '::'

            if tmp_node.type == 'identifier':
                tmp_name = tmp_node.text.decode()
                break
            if tmp_node.type == 'field_identifier':
                tmp_name = tmp_node.text.decode()
                break
            if tmp_node.child_by_field_name(
                    'name') is not None and tmp_node.child_by_field_name(
                        'name').type == 'identifier':
                tmp_name = tmp_node.child_by_field_name('name').text.decode()
            tmp_node = tmp_node.child_by_field_name('declarator')
        if tmp_name:
            logger.debug('Assigning name')
            full_name = full_name + scope_to_add + tmp_name
        else:
            logger.debug('Assigning name as signature')
            full_name = self.sig

        # try:
        #    full_name = full_name + self.root.child_by_field_name(
        #    'declarator').child_by_field_name(
        #    'declarator').child_by_field_name(
        #    'declarator').text.decode()
        # except:
        #    try:
        #        full_name = full_name + self.root.child_by_field_name(
        #        'declarator').child_by_field_name('declarator').text.decode()
        #    except:

        # This can happen for e.g. operators
        #    full_name = self.sig
        logger.debug('Full function name: %s', full_name)
        self.name = full_name
        logger.debug('Done walking')

        # Handles class or namespace in the function name
        if '::' in self.name:
            self.namespace_or_class, _ = self.name.rsplit('::', 1)

        # Handles return type
        type_node = self.root.child_by_field_name('type')
        if type_node:
            self.return_type = type_node.text.decode()
        else:
            self.return_type = 'void'

        # Handles parameters
        if param_list_node:
            for param in param_list_node.children:
                if param.type == 'parameter_declaration':
                    param_type = param.child_by_field_name('type')
                    param_name = param.child_by_field_name('declarator')

                    # Skip empty param name and type
                    if not param_type or param_name:
                        continue

                    while param_name is not None and param_name.type not in [
                            'identifier', 'qualified_identifier',
                            'pointer_declarator', 'array_declarator',
                            'reference_declarator'
                    ]:
                        param_name = param_name.child_by_field_name(
                            'declarator')
                        if param_name is None:
                            break

                    if not param_name:
                        continue

                    result = self._extract_pointer_array_from_type(param_name)
                    pcount, acount, param_name = result

                    self.arg_types.append(
                        f'{param_type.text.decode()}{"*" * pcount}'
                        f'{"[]" * acount}')
                    self.arg_names.append(param_name.text.decode().replace(
                        '&', ''))
                    self.var_map[self.arg_names[-1]] = self.arg_types[-1]

        # Handles other fields
        self._process_complexity()
        self._process_icount()

    def _process_complexity(self):
        """Gets complexity measure based on counting branch nodes in a
        function."""

        branch_nodes = [
            'if_statement', 'switch_statement', 'do_statement',
            'while_statement', 'for_statement', 'for_range_loop',
            'try_statement', 'seh_try_statement', 'throw_statement',
            'goto_statement', 'co_return_statement', 'co_yield_statement',
            'break_statement', 'continue_statement', '&&', '||'
        ]

        def _traverse_node_complexity(node: Node):
            count = 0
            if node.type in branch_nodes:
                count += 1
            for item in node.children:
                count += _traverse_node_complexity(item)
            return count

        self.complexity += _traverse_node_complexity(self.root)

    def _process_icount(self):
        """Get a pseudo measurement of instruction count."""

        def _traverse_node_instr_count(node: Node) -> int:
            count = 0
            if 'statement' in node.type:
                count += 1
            for item in node.children:
                count += _traverse_node_instr_count(item)
            return count

        self.icount += _traverse_node_instr_count(self.root)

    def _process_invoke(self, expr: Node,
                        project) -> list[tuple[str, int, int]]:
        """Internal helper for processing the function invocation statement."""
        # logger.debug('Current namespace: %s', self.namespace_or_class)
        logger.debug('Processing invoke: %s',
                     expr.text.decode() if expr.text else '')
        callsites = []
        target_name: str = ''

        func = expr.child_by_field_name('function')

        # Handle function call
        if func:
            # Simple function call
            # identifier indicates general function calls
            # qualified_identifier indicates namespace function calls
            # template_function indicates standard function calls
            if func.type in [
                    'identifier', 'qualified_identifier', 'template_function'
            ] and func.text:
                target_name = func.text.decode()

                # Find the matching function in our project
                matched_func = get_function_node(
                    target_name,
                    project.all_functions,
                    namespace=self.namespace_or_class)
                if matched_func:
                    logger.debug('Matched function: %s', matched_func.name)
                    target_name = matched_func.name
                else:
                    name_node = func.child_by_field_name('name')
                    if name_node and name_node.text:
                        target_name2 = name_node.text.decode()
                        matched_func2 = get_function_node(
                            target_name2,
                            project.all_functions,
                            namespace=self.namespace_or_class)
                        if matched_func2:
                            logger.debug('Matched function: %s',
                                         matched_func2.name)
                            target_name = matched_func2.name
                    logger.debug('Did not find matching function')

            # Chained or method calls
            elif func.type == 'field_expression':
                _, target_name = self._process_field_expr_return_type(
                    func, project)

        if target_name:
            # Handles in scope invocation
            if '::' not in target_name and self.namespace_or_class:
                full_target_name = f'{self.namespace_or_class}::{target_name}'
                for tmp_func in project.all_functions:
                    if tmp_func.name == full_target_name:
                        # if full_target_name in project.all_functions:
                        target_name = full_target_name
                        break

            if func and func.start_point:
                callsites.append((target_name, func.byte_range[1],
                                  func.start_point.row + 1))

        return callsites

    def _process_field_expr_return_type(self, field_expr: Node,
                                        project) -> tuple[Optional[str], str]:
        """Helper for determining the return type of a field expression
        in a chained call and its full qualified name."""
        # logger.debug('Handling field expression: %s',field_expr.text.decode())
        ret_type = None
        object_type = None

        arg = field_expr.child_by_field_name('argument')
        field = field_expr.child_by_field_name('field')

        if not arg or not field:
            return (None, '')

        if field.type == 'template_method':
            name_node = field.child_by_field_name('name')
            full_name = (name_node.text.decode()
                         if name_node and name_node.text else '')
        else:
            full_name = field.text.decode() if field.text else ''

        # Chained field access
        if arg.type == 'field_expression':
            _, object_type = self._process_field_expr_return_type(arg, project)

        # Internal call
        elif arg.type == 'this':
            object_type = self.namespace_or_class

        # Named object
        elif arg.type in ['identifier', 'qualified_identifier']:
            if arg.text:
                object_type = self.var_map.get(arg.text.decode())
        elif arg.type == 'call_expression':
            # Bail, we do not support this yet. Examples of code:
            # "static_cast<impl::xpath_query_impl*>(_impl)->root->eval_string
            # (c, sd.stack);""
            # We give up here.
            logger.debug('Cant analyse this.')
            return ('', '')

        if object_type:
            if object_type != 'void':
                full_name = f'{object_type}::{full_name}'

            node = get_function_node(full_name, project.all_functions)
            if node:
                ret_type = node.return_type

        return (ret_type, full_name)

    def _process_callsites(self, stmt: Node,
                           project) -> list[tuple[str, int, int]]:
        """Process and store the callsites of the function."""
        logger.debug('Processing callsite: %s',
                     stmt.text.decode() if stmt.text else '')
        callsites = []

        # Call statement
        if stmt.type == 'call_expression':
            # logger.debug('Handling call expression: %s', stmt.text.decode())
            callsites.extend(self._process_invoke(stmt, project))

        # Constructor call statement
        elif stmt.type == 'new_expression':
            # logger.debug('Handling new_expression: %s', stmt.text.decode())
            ctr_type = stmt.child_by_field_name('type')
            if ctr_type and ctr_type.text:
                cls = ctr_type.text.decode()
                cls = f'{cls}::{cls.rsplit("::")[-1]}'
                callsites.append(
                    (cls, stmt.byte_range[1], stmt.start_point.row + 1))

        elif stmt.type == 'declaration':
            # logger.debug('Handling declaration: %s', stmt.text.decode())
            var_type = ''
            var_type_obj = stmt.child_by_field_name('type')

            if var_type_obj is None:
                return []

            if var_type_obj.type in ['primitive_type', 'sized_type_specifier']:
                logger.debug('Skipping.')
                return []

            while True:
                if var_type_obj is None:
                    return []
                if var_type_obj.type == 'qualified_identifier':
                    if var_type_obj.child_by_field_name('scope') is not None:
                        scope = var_type_obj.child_by_field_name('scope')
                        if scope and scope.text:
                            var_type += scope.text.decode()
                    var_type += '::'
                    var_type_obj = var_type_obj.child_by_field_name('name')

                if var_type_obj and var_type_obj.type == 'template_type':
                    template_name = var_type_obj.child_by_field_name('name')
                    if template_name and template_name.text:
                        var_type += template_name.text.decode()
                else:
                    var_type += (var_type_obj.text.decode()
                                 if var_type_obj and var_type_obj.text else '')

                break

            try:
                var_name = stmt.child_by_field_name('declarator')
            except AttributeError:
                var_name = None

            if not var_name or not var_name.text:
                logger.debug('Could not extract necessary attributes')
                return []

            logger.debug('Extracted declaration: Type `%s` : Name `%s`',
                         var_type, var_name.text.decode())
            # Handles implicit default constructor call
            if var_name.type == 'identifier':
                # We're looking for a constructor, so add the name as it
                # should be the name of the constructor.
                cls = f'{var_type}::{var_type.rsplit("::")[-1]}'
                logger.debug('Trying to find class %s', cls)
                # added = False
                # if cls in project.all_functions:
                if project.get_function_from_name(cls):
                    logger.debug('Adding callsite')
                    # added = True
                    callsites.append(
                        (cls, stmt.byte_range[1], stmt.start_point.row + 1))
                # if not added:
                #    logger.debug('Trying a hacky match.')
                #    # Hack to make sure we add in case our analysis of
                #    # constructors was wrong. TODO(David) fix.
                #    cls = var_type
                #    if cls in project.all_functions:
                #        logger.debug('Adding callsite')
                #        added = True
                #        callsites.append((cls, stmt.byte_range[1],
                #                          stmt.start_point.row + 1))
            while var_name is not None and var_name.type not in [
                    'identifier', 'qualified_identifier', 'pointer_declarator',
                    'array_declarator', 'reference_declarator'
            ]:
                var_name = var_name.child_by_field_name('declarator')

            if var_name is None:
                return []

            result = self._extract_pointer_array_from_type(var_name)
            pcount, acount, var_name = result
            var_type = f'{var_type}{"*" * pcount}{"[]" * acount}'
            name_text = var_name.text
            if name_text:
                self.var_map[name_text.decode().replace('&', '')] = var_type

        for child in stmt.children:
            callsites.extend(self._process_callsites(child, project))

        return callsites

    def extract_callsites(self, project):
        """Gets the callsites of the function."""

        if not self.base_callsites:
            callsites = []
            for child in self.root.children:
                try:
                    callsites.extend(self._process_callsites(child, project))
                except UnicodeDecodeError:
                    logger.debug('Error decoding statement.')

            callsites = sorted(set(callsites), key=lambda x: x[1])
            self.base_callsites = [(x[0], x[2]) for x in callsites]

        if not self.detailed_callsites:
            for dst, src_line in self.base_callsites:
                src_loc = f'{self.parent_source.source_file}:{src_line},1'
                self.detailed_callsites.append({'Src': src_loc, 'Dst': dst})


class CppProject(datatypes.Project[CppSourceCodeFile]):
    """Wrapper for doing analysis of a collection of source files."""

    def __init__(self, source_code_files: list[CppSourceCodeFile]):
        super().__init__(source_code_files)

    def generate_report(self,
                        entry_function: str = '',
                        harness_name: str = '',
                        harness_source: str = '') -> None:
        """Helper function for generating yaml function report."""
        # pylint: disable=unused-argument

        self.report['report'] = 'name'
        self.report['sources'] = []
        self.report['Fuzzing method'] = 'LLVMFuzzerTestOneInput'
        self.report['Fuzzer filename'] = harness_source

        self.all_functions = []
        for source_code in self.source_code_files:
            # Log entry method if provided

            # Retrieve project information
            func_names = [func.name for func in source_code.func_defs]

            self.report['sources'].append({
                'source_file': source_code.source_file,
                'function_names': func_names,
            })

            for func in source_code.func_defs:
                self.all_functions.append(func)

        # Process all project functions
        func_list = []
        for func in self.all_functions:
            logger.debug('Iterating %s', func.name)
            logger.debug('Extracing callsites')
            func.extract_callsites(self)
            logger.debug('Done extracting callsites')
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
            logger.debug('Calculating function uses')
            func_dict['functionUses'] = self.calculate_function_uses(func.name)
            logger.debug('Getting function depth')
            func_dict['functionDepth'] = self.calculate_function_depth(func)
            func_dict['constantsTouched'] = []
            func_dict['BBCount'] = 0
            func_dict['signature'] = func.sig
            callsites = func.base_callsites
            reached = set()
            for cs_dst, _ in callsites:
                reached.add(cs_dst)
            func_dict['functionsReached'] = list(reached)

            logger.debug('Done')
            func_list.append(func_dict)

        if func_list:
            self.report['All functions'] = {}
            self.report['All functions']['Elements'] = func_list

        self.report['Fuzzing method'] = 'LLVMFuzzerTestOneInput'
        self.report['Fuzzer filename'] = harness_source

    def get_function_from_name(self, function_name):
        for func in self.all_functions:
            if func.name == function_name:
                return func

        return None

    def extract_calltree(self,
                         source_file: str = '',
                         source_code: Optional[CppSourceCodeFile] = None,
                         function: Optional[str] = None,
                         visited_functions: Optional[set[str]] = None,
                         depth: int = 0,
                         line_number: int = -1,
                         other_props: Optional[dict[str, Any]] = None) -> str:
        """Extracts calltree string of a calltree so that FI core can use it."""
        # pylint: disable=unused-argument

        # Create calltree from a given function
        # Find the function in the source code
        logger.debug('Extracting calltree for %s', str(function))
        if not visited_functions:
            visited_functions = set()

        if not function:
            logger.debug('No function')
            return ''

        if not source_code:
            result = self.find_source_with_func_def(function)
            if result:
                source_code = result[0]

        func_node = None
        if function:
            if source_code:
                logger.debug('Using source code var to extract node')
                func_node = source_code.get_function_node(function)
            else:
                logger.debug('Extracting node using lookup table.')
                func_node = get_function_node(function, self.all_functions)

            if func_node:
                logger.debug('Found function node: %s', func_node.name)
                func_name = func_node.name
            else:
                logger.debug('Found no function node')
                func_name = function
        else:
            logger.debug('Could not find function')
            return ''

        line_to_print = '  ' * depth
        line_to_print += func_name
        line_to_print += ' '
        line_to_print += source_file

        line_to_print += ' '
        line_to_print += str(line_number)

        line_to_print += '\n'
        if func_node and not source_code:
            source_code = func_node.parent_source

        if function in visited_functions or not func_node or not source_code:
            if function in visited_functions:
                logger.debug('Function in visited ')
            if not func_node:
                logger.debug('Not func_node')
            if not source_code:
                logger.debug('Not source code')
            logger.debug('Function visited or no function node')
            return line_to_print

        visited_functions.add(function)
        logger.debug('Iterating %s callsites', len(func_node.base_callsites))
        for cs, line in func_node.base_callsites:
            logger.debug('Callsite: %s', cs)
            line_to_print += self.extract_calltree(
                source_file=source_code.source_file,
                function=cs,
                visited_functions=visited_functions,
                depth=depth + 1,
                line_number=line)
        logger.debug('Done')
        return line_to_print

    def get_reachable_functions(
            self,
            source_file: str = '',
            source_code: Optional[CppSourceCodeFile] = None,
            function: Optional[str] = None,
            visited_functions: Optional[set[str]] = None) -> set[str]:
        """Gets the reachable frunctions from a given function."""
        # pylint: disable=unused-argument

        # Create calltree from a given function
        # Find the function in the source code
        if not visited_functions:
            visited_functions = set()

        if not function:
            return visited_functions

        source_code = None
        result = self.find_source_with_func_def(function)
        if result:
            source_code = result[0]

        func_node = None
        if function:
            func_node = get_function_node(function, self.all_functions)
            if func_node:
                func_name = func_node.name
                prefix = func_node.namespace_or_class
                if prefix:
                    func_name = f'{prefix}::{func_name}'
            else:
                func_name = function
        else:
            visited_functions.add(function)
            return visited_functions

        visited_functions.add(function)
        if not func_node or not source_code:
            return visited_functions

        for cs, _ in func_node.base_callsites:
            if cs in visited_functions:
                continue

            visited_functions = self.get_reachable_functions(
                source_code=source_code,
                function=cs,
                visited_functions=visited_functions,
            )

        return visited_functions

    def find_function_from_approximate_name(
            self, function_name: str) -> Optional['FunctionDefinition']:
        """Locate a function element with name approximately."""
        function_names = []
        for func in self.all_functions:
            if func.name == function_name:
                function_names.append(func)
        if len(function_names) == 1:
            return function_names[0]

        function_names = []
        for func in self.all_functions:
            if func.name.endswith(function_name):
                function_names.append(func)
        if len(function_names) == 1:
            return function_names[0]

        return None

    def find_source_with_func_def(
            self, name: str
    ) -> Optional[tuple[CppSourceCodeFile, FunctionDefinition]]:
        """Finds the source code with a given function."""

        return_func = None
        source_codes_with_target = []
        for source_code in self.source_code_files:
            func = source_code.get_function_node(name, exact=True)
            if func:
                return_func = func
                source_codes_with_target.append(source_code)

        if len(source_codes_with_target) == 1 and return_func:
            # We hav have, in this case it's trivial.
            return (source_codes_with_target[0], return_func)

        return_func = None
        source_codes_with_target = []
        for source_code in self.source_code_files:
            func = source_code.get_function_node(name, exact=False)
            if func:
                return_func = func
                source_codes_with_target.append(source_code)

        if len(source_codes_with_target) == 1 and return_func:
            # We hav have, in this case it's trivial.
            return (source_codes_with_target[0], return_func)

        # TODO Handle multiple match (matching the namespace and class also

        return None

    def calculate_function_uses(self, target_name: str) -> int:
        """Calculate how many functions called the target function."""
        func_use_count = 0

        for source_file in self.source_code_files:
            for function in source_file.func_defs:
                found = False
                for callsite in function.base_callsites:
                    if callsite[0] == target_name:
                        found = True
                        break
                    if callsite[0].endswith(target_name):
                        found = True
                        break
                if found:
                    func_use_count += 1

        return func_use_count

    def calculate_function_depth(self,
                                 target_function: FunctionDefinition) -> int:
        """Calculate function depth of the target function."""

        def _recursive_function_depth(function: FunctionDefinition) -> int:
            if function.depth != -1:
                return function.depth

            callsites = function.base_callsites
            if len(callsites) == 0:
                return 0

            depth = 0
            visited.append(function.name)
            for callsite in callsites:
                target = self.find_source_with_func_def(callsite[0])
                if target and target[1].name in visited:
                    depth = max(depth, 1)
                elif target:
                    depth = max(depth,
                                _recursive_function_depth(target[1]) + 1)
                    function.depth = depth
                else:
                    visited.append(callsite[0])

            return depth

        visited: list[str] = []
        func_depth = _recursive_function_depth(target_function)

        return func_depth


def load_treesitter_trees(source_files, is_log=True) -> CppProject:
    """Creates treesitter trees for all files in a given list of
    source files."""
    results = []

    for code_file in source_files:
        if not os.path.isfile(code_file):
            continue

        try:
            source_cls = CppSourceCodeFile('c++', code_file)
        except RecursionError:
            continue
        results.append(source_cls)

        if is_log:
            if source_cls.has_libfuzzer_harness():
                logger.info('harness: %s', code_file)

    return CppProject(results)


def analyse_source_code(source_content: str) -> CppSourceCodeFile:
    """Returns a source abstraction based on a single source string."""
    source_code = CppSourceCodeFile('c++',
                                    source_file='in-memory string',
                                    source_content=source_content.encode())
    return source_code


def get_function_node(target_name: str,
                      function_list: list[FunctionDefinition],
                      one_layer_only: bool = False,
                      namespace: str = '') -> Optional[FunctionDefinition]:
    """Helper to retrieve the RustFunction object of a function."""

    logger.debug('Finding match for %s', target_name)
    for function in function_list:
        if target_name == function.name:
            logger.debug('Found exact match')
            return function

    if namespace:
        logger.debug('Finding function within namespace %s', namespace)
        for function in function_list:
            if namespace + '::' + target_name == function.name:
                logger.debug('Found namespace match')
                return function

    # Exact match
    # if target_name in function_map:
    #     return function_map[target_name]
    if '::' not in target_name:
        return None

    # Avoid all references to std library for the heuristics that are follow.
    # This is because we do approximate namespace matching, and functions
    # from standard library are definitely not imlemented in any library we
    # analyse.
    if target_name.startswith('std::'):
        return None

    # Match any key that ends with target_name, then
    # split the target_name by :: and check one by one
    if one_layer_only:
        name_split = target_name.split('::', 1)
    else:
        name_split = target_name.split('::')

    for count in range(len(name_split)):
        logger.debug('Testing %s', '::'.join(name_split[count:]))
        for func in function_list:
            if func.name.endswith('::'.join(name_split[count:])):
                logger.debug('Found match: %s', func.name)
                return func

    logger.debug('Found no matching function node')
    return None
