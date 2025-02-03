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

from typing import Any, Optional

from tree_sitter import Language, Node

import logging
import yaml

from fuzz_introspector.frontends.datatypes import Project, SourceCodeFile

logger = logging.getLogger(name=__name__)

FUZZING_METHOD_RETURN_TYPE_MAP = {
    "consumeBoolean": "boolean",
    "consumeBooleans": "boolean[]",
    "consumeByte": "byte",
    "consumeBytes": "byte[]",
    "consumeRemainingAsBytes": "byte[]",
    "consumeShort": "short",
    "consumeShorts": "short[]",
    "consumeInt": "int",
    "consumeInts": "int[]",
    "consumeLong": "long",
    "consumeLongs": "long[]",
    "consumeFloat": "float",
    "consumeRegularFloat": "float",
    "consumeProbabilityFloat": "float",
    "consumeDouble": "double",
    "consumeRegularDouble": "double",
    "consumeProbabilityDouble": "double",
    "consumeChar": "char",
    "consumeCharNoSurrogates": "char",
    "consumeString": "String",
    "consumeRemainingAsString": "String",
    "consumeAsciiString": "String",
    "consumeRemainingAsAsciiString": "String",
    "remainingBytes": "int"
}

LITERAL_MAP = {
    "decimal_integer_literal": "int",
    "hex_integer_literal": "int",
    "octal_integer_literal": "int",
    "binary_integer_literal": "int",
    "decimal_floating_point_literal": "float",
    "hex_floating_point_literal": "float",
    "true": "boolean",
    "false": "boolean",
    "character_literal": "char",
    "string_literal": "String",
    "null_literal": "null"
}


class JvmSourceCodeFile(SourceCodeFile):
    """Class for holding file-specific information."""

    def language_specific_process(self) -> None:
        """Perform some language specific processes in subclasses."""
        # List of definitions in the source file.
        self.package = ''
        self.classes: list['JavaClassInterface'] = []
        self.imports: dict[str, str] = {}

        # Initialization ruotines
        self.load_tree()

        # Load package declaration
        self._set_package_declaration()

        # Load classes/interfaces delcaration
        self._set_class_interface_declaration()

        # Load import statements
        self._set_import_declaration()

    def post_process_imports(self, classes: list['JavaClassInterface']):
        """Add in full qualified name for classes in projects."""
        for cls in classes:
            name = cls.name
            if name.rsplit('.', 1)[-1] not in self.imports:
                self.imports[name.rsplit('.', 1)[-1]] = name

    def _set_package_declaration(self):
        """Internal helper for retrieving the source package."""
        query = self.tree_sitter_lang.query('( package_declaration ) @fd ')
        res = query.captures(self.root)
        for _, nodes in res.items():
            for node in nodes:
                for package in node.children:
                    if package.type in ['scoped_identifier', 'identifier']:
                        self.package = package.text.decode()

    def _set_class_interface_declaration(self):
        """Internal helper for retrieving all classes."""
        for node in self.root.children:
            if node.type in ['class_declaration', 'interface_declaration']:
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

    def get_all_methods(self) -> dict[str, 'JavaMethod']:
        """Gets all JavaMethod object of all classes in this source file,
        mapped by its method name"""
        methods = {}
        for cls in self.classes:
            for method in cls.get_all_methods():
                methods[method.name] = method

        return methods

    def get_method_node(self, target_name: str) -> Optional['JavaMethod']:
        """Gets the tree-sitter node corresponding to a method."""
        methods = self.get_all_methods()
        return methods.get(target_name, None)

    def get_entry_method_name(self,
                              is_full_name: bool = False) -> Optional[str]:
        """Returns the entry method name of the harness if found,"""
        for cls in self.classes:
            entry = cls.get_entry_method_name()
            if entry:
                if is_full_name:
                    return entry

                return entry.split('].')[-1].split('(')[0]

        return None

    def get_full_qualified_name(self, type_str: str) -> str:
        """Process the full qualified name for type from imports."""
        processed_parts = []
        buffer = ''

        # Remove all spaces
        type_str = type_str.replace(' ', '')

        # Define delimiters for handling generic types
        delimiters = ['<', '>', ',']

        for char in type_str:
            if char in delimiters:
                if '.' not in buffer and buffer in self.imports:
                    processed_parts.append(self.imports[buffer])
                else:
                    processed_parts.append(buffer)
                processed_parts.append(char)
                buffer = ''
            else:
                buffer += char

        if buffer:
            if '.' not in buffer and buffer in self.imports:
                processed_parts.append(self.imports[buffer])
            else:
                processed_parts.append(buffer)

        return ''.join(processed_parts)

    def has_libfuzzer_harness(self) -> bool:
        """Returns whether the source code holds a libfuzzer harness"""
        if any(cls.has_libfuzzer_harness() for cls in self.classes):
            return True

        return False

    def has_method_definition(self, target_name: str) -> bool:
        """Returns if the source file holds a given function definition."""
        if any(
                cls.has_method_definition(target_name)[0]
                for cls in self.classes):
            return True

        return False

    def has_class(self, target_name: str) -> bool:
        """Returns if the class exist in this source file."""
        if any(cls.name.endswith(target_name) for cls in self.classes):
            return True

        return False


class JavaMethod():
    """Wrapper for a General Declaration for method"""

    def __init__(self,
                 root: Node,
                 class_interface: 'JavaClassInterface',
                 is_constructor: bool = False,
                 is_default_constructor: bool = False):
        self.root = root
        self.class_interface = class_interface
        self.tree_sitter_lang = self.class_interface.tree_sitter_lang
        self.parent_source: Optional[
            JvmSourceCodeFile] = self.class_interface.parent_source
        self.is_constructor = is_constructor
        self.is_default_constructor = is_default_constructor
        self.name: str = ''

        # Store method line information
        if self.is_default_constructor:
            self.start_line = -1
            self.end_line = -1
            self.name = '<init>'
            self.public = True
        else:
            self.start_line = self.root.start_point.row + 1
            self.end_line = self.root.end_point.row + 1
            self.name = ''
            self.public = False

        # Other properties
        self.complexity = 0
        self.icount = 0
        self.arg_names: list[str] = []
        self.arg_types: list[str] = []
        self.exceptions: list[str] = []
        self.return_type = ''
        self.function_uses = 0
        self.function_depth = 0
        self.base_callsites: list[tuple[str, int]] = []
        self.detailed_callsites: list[dict[str, str]] = []
        self.concrete = True
        self.static = False
        self.is_entry_method = False

        # Other properties
        self.stmts: list[Node] = []
        self.var_map: dict[str, str] = {}

        if not self.is_default_constructor:
            # Process method declaration
            self._process_declaration()

            # Process statements
            self._process_statements()

    def post_process_full_qualified_name(self):
        """Post process the full qualified name for types."""
        # Refine argument types
        self.arg_types = [
            self.parent_source.get_full_qualified_name(arg_type)
            for arg_type in self.arg_types
        ]

        # Refine name
        class_name = self.parent_source.get_full_qualified_name(
            self.class_interface.name)
        if '[' not in self.name and '].' not in self.name:
            self.name = (f'[{class_name}].{self.name}'
                         f'({",".join(self.arg_types)})')

        # Refine variable map
        for key in self.var_map:
            self.var_map[key] = self.parent_source.get_full_qualified_name(
                self.var_map[key])

        # Refine return type
        if self.is_constructor:
            self.return_type = class_name
        else:
            self.return_type = self.parent_source.get_full_qualified_name(
                self.return_type)

        # Refine exceptions
        self.exceptions = [
            self.parent_source.get_full_qualified_name(exception)
            for exception in self.exceptions
        ]

    def _process_declaration(self):
        """Internal helper to process the method declaration."""
        for child in self.root.children:
            # Process name
            if child.type == 'identifier':
                if self.is_constructor:
                    self.name = '<init>'
                else:
                    self.name = child.text.decode()
                    if self.name == self.parent_source.entrypoint:
                        self.is_entry_method = True

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
                        arg_name = argument.child_by_field_name(
                            'name').text.decode()
                        arg_type = argument.child_by_field_name(
                            'type').text.decode()

                        self.arg_names.append(arg_name)
                        self.arg_types.append(arg_type)
                        self.var_map[arg_name] = arg_type

            # Process return type
            elif child.type.endswith('type_identifier') or child.type.endswith(
                    '_type'):
                self.return_type = child.text.decode()

            # Process body and store statment nodes
            elif child.type in ['block', 'constructor_body']:
                for stmt in child.children:
                    if stmt.type not in ['{', '}'
                                         ] and 'comment' not in stmt.type:
                        self.stmts.append(stmt)

            # Process exceptions
            elif child.type == 'throws':
                for exception in child.children:
                    if exception.type.endswith('type_identifier'):
                        self.exceptions.append(exception.text.decode())

    def _process_statements(self):
        """Loop through all statements and process them."""
        for stmt in self.stmts:
            self._process_complexity(stmt)
            self._process_icount(stmt)

    def _process_complexity(self, stmt: Node):
        """Gets complexity measure based on counting branch nodes in a
        function."""

        branch_nodes = [
            'if_statement',
            'while_statsment',
            'for_statement',
            'enhanced_for_statement',
            'do_statement',
            'break_statement',
            'continue_statement',
            'return_statement',
            'yield_statement',
            'switch_label',
            'throw_statement',
            'try_statement',
            'try_with_resources_statement',
            'catch_clause',
            'finally_clause',
            'lambda_expression',
            'ternary_expression',
            'switch_expression',
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

        self.complexity += _traverse_node_complexity(stmt)

    def _process_icount(self, stmt: Node):
        """Get a pseudo measurement of instruction count."""

        instr_nodes = [
            'assignment_expression',
            'binary_expression',
            'instanceof_expression',
            'lambda_expression',
            'ternary_expression',
            'update_expression',
            'primary_expression',
            'unary_expression',
            'cast_expression',
            'switch_expression',
            'object_creation_expression',
            'array_creation_expression',
            'method_invocation',
            'explicit_constructor_invocation',
        ]

        def _traverse_node_instr_count(node: Node) -> int:
            count = 0
            if node.type in instr_nodes:
                count += 1
            for item in node.children:
                count += _traverse_node_instr_count(item)
            return count

        self.icount += _traverse_node_instr_count(stmt)

    def _process_invoke_object(
        self, stmt: Node, classes: dict[str, 'JavaClassInterface']
    ) -> tuple[str, list[tuple[str, int, int]]]:
        """Internal helper for processing the object from a invocation."""
        callsites: list[tuple[str, int, int]] = []
        return_value = ''

        # Handle literal value
        if stmt.type in LITERAL_MAP:
            return_value = LITERAL_MAP[stmt.type]

        # Determine the type of the object
        elif stmt.child_count == 0:
            # Class call
            if stmt.type == 'this':
                return_value = self.class_interface.name

            # SuperClass call
            elif stmt.type == 'super':
                return_value = self.class_interface.super_class

            # Variable call or static call
            else:
                var_name = stmt.text.decode() if stmt.text else ''
                return_value = self.var_map.get(var_name, '')
                if not return_value:
                    return_value = self.class_interface.class_fields.get(
                        var_name, '')
                if not return_value and self.parent_source:
                    return_value = self.parent_source.imports.get(var_name, '')
        else:
            # Field access
            if stmt.type == 'field_access':
                obj = stmt.child_by_field_name('object')
                field = stmt.child_by_field_name('field')

                if obj and field:
                    object_class, callsites = self._process_invoke_object(
                        obj, classes)
                    cls = classes.get(object_class)
                    if cls and field.text:
                        return_value = cls.class_fields.get(
                            field.text.decode(), self.class_interface.name)

            # Chained call
            elif stmt.type == 'method_invocation':
                return_value, invoke_callsites = self._process_invoke(
                    stmt, classes)
                callsites.extend(invoke_callsites)

            # Chained call from constructor
            elif stmt.type == 'object_creation_expression':
                return_value, invoke_callsites = self._process_invoke(
                    stmt, classes, True)
                callsites.extend(invoke_callsites)
            elif stmt.type == 'explicit_constructor_invocation':
                return_value, invoke_callsites = self._process_invoke(
                    stmt, classes, True)
                callsites.extend(invoke_callsites)

            # Casting expression in Parenthesized statement
            elif stmt.type == 'parenthesized_expression':
                for cast in stmt.children:
                    if cast.type == 'cast_expression' and self.parent_source:
                        value = cast.child_by_field_name('value')
                        cast_type = cast.child_by_field_name('type')
                        if not value or not cast_type or not cast_type.text:
                            continue
                        return_value = (
                            self.parent_source.get_full_qualified_name(
                                cast_type.text.decode()))

                        if value.type == 'method_invocation':
                            _, invoke_callsites = self._process_invoke(
                                value, classes)
                            callsites.extend(invoke_callsites)
                        elif value.type == 'object_creation_expression':
                            _, invoke_callsites = self._process_invoke(
                                value, classes, True)
                            callsites.extend(invoke_callsites)
                        elif value.type == 'explicit_constructor_invocation':
                            _, invoke_callsites = self._process_invoke(
                                value, classes, True)
                            callsites.extend(invoke_callsites)

        return return_value, callsites

    def _process_invoke_args(
        self, stmt: Node, classes: dict[str, 'JavaClassInterface']
    ) -> tuple[list[str], list[tuple[str, int, int]]]:
        """Internal helper for processing the object from a invocation."""
        callsites = []
        return_values = []

        for argument in stmt.children:
            return_value = self.class_interface.name

            # Handling literal value
            if argument.type in LITERAL_MAP:
                return_values.append(LITERAL_MAP[argument.type])

            # Binary expression
            elif argument.type == 'binary_expression':
                found = False
                other_type_node = []

                # Try locate literal values
                for child in argument.children:
                    if child.type in LITERAL_MAP:
                        return_values.append(LITERAL_MAP[child.type])
                        found = True
                    else:
                        other_type_node.append(child)

                # Only store type value is not found
                for node in other_type_node:
                    return_value, invoke = self._process_invoke(node, classes)

                    if return_value and not found:
                        found = True
                        return_values.append(return_value)
                    callsites.extend(invoke)

            # Variables
            elif argument.type == 'identifier':
                arg_name = argument.text.decode() if argument.text else ''
                return_value = self.var_map.get(arg_name, '')
                if not return_value:
                    return_value = self.class_interface.class_fields.get(
                        arg_name, self.class_interface.name)
                return_values.append(return_value)

            # Method invocation
            elif argument.type == 'method_invocation':
                return_value, invoke_callsites = self._process_invoke(
                    argument, classes)
                callsites.extend(invoke_callsites)
                return_values.append(return_value)

            # Constructor invocation
            elif argument.type == 'object_creation_expression':
                return_value, invoke_callsites = self._process_invoke(
                    argument, classes, True)
                callsites.extend(invoke_callsites)
                return_values.append(return_value)
            elif argument.type == 'explicit_constructor_invocation':
                return_value, invoke_callsites = self._process_invoke(
                    argument, classes, True)
                callsites.extend(invoke_callsites)
                return_values.append(return_value)

            # Field or static variable access
            elif argument.type == 'field_access':
                obj = argument.child_by_field_name('object')
                field = argument.child_by_field_name('field')

                if obj and field:
                    object_class, callsites = self._process_invoke_object(
                        obj, classes)
                    cls = classes.get(object_class)
                    if cls and field.text:
                        return_value = cls.class_fields.get(
                            field.text.decode(), self.class_interface.name)
                return_values.append(return_value)

            # Type casting expression
            elif argument.type == 'cast_expression' and self.parent_source:
                value = argument.child_by_field_name('value')
                cast_type = argument.child_by_field_name('type')
                if not value or not cast_type or not cast_type.text:
                    continue

                return_value = self.parent_source.get_full_qualified_name(
                    cast_type.text.decode())

                if value.type == 'method_invocation':
                    _, invoke_callsites = self._process_invoke(value, classes)
                    callsites.extend(invoke_callsites)
                elif value.type == 'object_creation_expression':
                    _, invoke_callsites = self._process_invoke(
                        value, classes, True)
                    callsites.extend(invoke_callsites)
                elif value.type == 'explicit_constructor_invocation':
                    _, invoke_callsites = self._process_invoke(
                        value, classes, True)
                    callsites.extend(invoke_callsites)

                return_values.append(return_value)

        return return_values, callsites

    def _process_invoke(
        self,
        expr: Node,
        classes: dict[str, 'JavaClassInterface'],
        is_constructor_call: bool = False
    ) -> tuple[str, list[tuple[str, int, int]]]:
        """Internal helper for processing the method invocation statement."""
        callsites = []

        # JVM method_invocation separated into three main items
        # <object>.<name>(<arguments>)
        objects = expr.child_by_field_name('object')
        name = expr.child_by_field_name('name')
        arguments = expr.child_by_field_name('arguments')

        # Recusive handling for method invocation in arguments
        if arguments:
            argument_types, argument_callsites = self._process_invoke_args(
                arguments, classes)
            callsites.extend(argument_callsites)
        else:
            argument_types = []

        # Process constructor call
        if is_constructor_call and self.parent_source:
            object_type = ''
            for cls_type in expr.children:
                if cls_type.type == 'this':
                    object_type = self.class_interface.name

                elif cls_type.type == 'super':
                    object_type = self.class_interface.super_class

                elif cls_type.type.endswith(
                        'type_identifier') or cls_type.type.endswith('_type'):
                    cls_name = cls_type.text.decode() if cls_type.text else ''
                    object_type = cls_name.split('<')[0]

            object_type = self.parent_source.get_full_qualified_name(
                object_type)

            for cls in classes.values():
                packaged_type = cls.add_package_to_class_name(object_type)
                if packaged_type:
                    object_type = packaged_type
                    break

            target_name = f'[{object_type}].<init>({",".join(argument_types)})'
            callsites.append(
                (target_name, expr.byte_range[1], expr.start_point.row + 1))

            return object_type, callsites

        # Recusive handling for method invocation in objects
        if objects:
            object_type, object_callsites = self._process_invoke_object(
                objects, classes)
            callsites.extend(object_callsites)
        else:
            object_type = self.class_interface.name

        # Process this method invocation
        target_name = ''
        if object_type and name and name.text:
            for cls in classes.values():
                packaged_type = cls.add_package_to_class_name(object_type)
                if packaged_type:
                    object_type = packaged_type
                    break

            target_name = (f'[{object_type}].{name.text.decode()}'
                           f'({",".join(argument_types)})')
            callsites.append(
                (target_name, expr.byte_range[1], expr.start_point.row + 1))

        # Calling to library outside of project
        # Preserve the full method call
        elif name and name.text:
            if objects and objects.text:
                target_name = (f'{objects.text.decode()}.{name.text.decode()}'
                               f'({",".join(argument_types)})')
            else:
                target_name = (f'{name.text.decode()}'
                               f'({",".join(argument_types)})')

            callsites.append(
                (target_name, expr.byte_range[1], expr.start_point.row + 1))

        # Determine return value from method invocation
        if object_type == 'com.code_intelligence.jazzer.api.FuzzedDataProvider':
            if name and name.text:
                return_type = FUZZING_METHOD_RETURN_TYPE_MAP.get(
                    name.text.decode(), '')
        else:
            return_type = self.class_interface.name
            if object_type in classes and target_name:
                _, method = classes[object_type].has_method_definition(
                    target_name, False)
                if method:
                    return_type = method.return_type

                _, method = classes[object_type].has_method_definition(
                    target_name, True)
                if method:
                    return_type = method.return_type

        return return_type, callsites

    def _process_callsites(
        self, stmt: Node, classes: dict[str, 'JavaClassInterface']
    ) -> tuple[str, list[tuple[str, int, int]]]:
        """Process and store the callsites of the method."""
        type_str = ''
        callsites: list[tuple[str, int, int]] = []

        if not stmt:
            return type_str, callsites

        if stmt.type == 'method_invocation':
            type_str, invoke_callsites = self._process_invoke(stmt, classes)
            callsites.extend(invoke_callsites)
        elif stmt.type == 'object_creation_expression':
            type_str, invoke_callsites = self._process_invoke(
                stmt, classes, True)
            callsites.extend(invoke_callsites)
        elif stmt.type == 'explicit_constructor_invocation':
            type_str, invoke_callsites = self._process_invoke(
                stmt, classes, True)
            callsites.extend(invoke_callsites)
        elif stmt.type == 'assignment_expression':
            left = stmt.child_by_field_name('left')
            right = stmt.child_by_field_name('right')
            if not left or not left.text or not right:
                return type_str, callsites

            var_name = left.text.decode().split(' ')[-1]
            type_str, invoke_callsites = self._process_callsites(
                right, classes)
            self.var_map[var_name] = type_str
            callsites.extend(invoke_callsites)
        elif stmt.type.endswith('local_variable_declaration'):
            for var_del in stmt.children:
                if var_del.type == 'variable_declarator':
                    name_node = var_del.child_by_field_name('name')
                    value_node = var_del.child_by_field_name('value')
                    if not name_node or not name_node.text or not value_node:
                        continue

                    var_name = name_node.text.decode()
                    type_str, invoke_callsites = self._process_callsites(
                        value_node, classes)
                    self.var_map[var_name] = type_str
                    callsites.extend(invoke_callsites)
        elif stmt.type.endswith('variable_declarator'):
            name_node = stmt.child_by_field_name('name')
            value_node = stmt.child_by_field_name('value')
            if not name_node or not name_node.text or not value_node:
                return type_str, callsites

            var_name = name_node.text.decode()
            type_str, invoke_callsites = self._process_callsites(
                value_node, classes)
            self.var_map[var_name] = type_str
            callsites.extend(invoke_callsites)
        else:
            for child in stmt.children:
                callsites.extend(self._process_callsites(child, classes)[1])

        return type_str, callsites

    def extract_callsites(self, classes: dict[str, 'JavaClassInterface']):
        """Extract callsites."""

        if not self.base_callsites:
            callsites = []
            for stmt in self.stmts:
                callsites.extend(self._process_callsites(stmt, classes)[1])
            if self.is_constructor:
                for stmt in self.class_interface.constructor_callsites:
                    callsites.extend(self._process_callsites(stmt, classes)[1])
            callsites = sorted(set(callsites), key=lambda x: x[1])
            self.base_callsites = [(x[0], x[2]) for x in callsites]

        if not self.detailed_callsites:
            for dst, src_line in self.base_callsites:
                src_loc = f'{self.class_interface.name}:{src_line},1'
                self.detailed_callsites.append({'Src': src_loc, 'Dst': dst})


class JavaClassInterface():
    """Wrapper for a General Declaration for java classes"""

    def __init__(self,
                 root: Node,
                 tree_sitter_lang: Language,
                 source_code: JvmSourceCodeFile,
                 parent: Optional['JavaClassInterface'] = None):
        self.root = root
        self.parent = parent
        self.tree_sitter_lang = tree_sitter_lang
        self.parent_source = source_code

        if self.parent:
            self.package = self.parent.name
        else:
            self.package = self.parent_source.package

        # Properties
        self.name: str = ''
        self.class_public = False
        self.class_concrete = True
        self.is_interface = False
        self.methods: list[JavaMethod] = []
        self.inner_classes: list[JavaClassInterface] = []
        self.class_fields: dict[str, str] = {}
        self.super_class = 'Object'
        self.super_interfaces: list[str] = []
        self.constructor_callsites: list[Node] = []

        # Process the class/interface tree
        inner_class_nodes = self._process_node()

        # Process inner classes
        self._process_inner_classes(inner_class_nodes)

        # Add in default constructor if no deinition of constructors
        if not self._has_constructor_defined():
            self.methods.append(JavaMethod(self.root, self, True, True))

    def add_package_to_class_name(self, name: str) -> Optional[str]:
        """Helper for finding a specific class name."""
        if self.name == f'{self.package}.{name.rsplit(".")[-1]}':
            if self.name.endswith(name):
                return self.name

        for inner_class in self.inner_classes:
            return inner_class.add_package_to_class_name(name)

        return None

    def post_process_full_qualified_name(self):
        """Post process the full qualified name for types."""
        # Refine class fields
        for key in self.class_fields:
            self.class_fields[
                key] = self.parent_source.get_full_qualified_name(
                    self.class_fields[key])

        # Refine all methods
        for method in self.methods:
            method.post_process_full_qualified_name()

        # Refine superclass
        self.super_class = self.parent_source.get_full_qualified_name(
            self.super_class)

        # Refine all super interfaces
        self.super_interfaces = [
            self.parent_source.get_full_qualified_name(interface)
            for interface in self.super_interfaces
        ]

    def _process_node(self) -> list[Node]:
        """Internal helper to process the Java classes/interfaces."""
        inner_class_nodes = []

        for child in self.root.children:
            # Process super class
            if child.type == 'superclass':
                for cls in child.children:
                    if cls.type.endswith('type_identifier') and cls.text:
                        self.super_class = cls.text.decode()

            # Process super interfaces
            elif child.type == 'super_interfaces':
                for interfaces in child.children:
                    if interfaces.type != 'type_list':
                        continue

                    type_set = set()
                    for interface in interfaces.children:
                        if (interface.type.endswith('type_identifier')
                                and interface.text):
                            type_set.add(interface.text.decode())
                    self.super_interfaces = list(type_set)

            # Process modifiers
            elif child.type == 'modifiers':
                for modifier in child.children:
                    modi_txt = modifier.text.decode() if modifier.text else ''
                    if modi_txt == 'public':
                        self.class_public = True
                    if modi_txt == 'abstract':
                        self.class_concrete = False

            # Process modifiers for interface
            elif child.type == 'interface':
                self.is_interface = True
                self.class_concrete = False

            # Process name
            elif child.type == 'identifier':
                self.name = child.text.decode() if child.text else ''
                if self.package:
                    self.name = f'{self.package}.{self.name}'

            # Process body
            elif child.type in ['class_body', 'interface_body']:
                for body in child.children:
                    # Process constructors
                    if body.type == 'constructor_declaration':
                        self.methods.append(JavaMethod(body, self, True))

                    # Process methods
                    elif body.type == 'method_declaration':
                        self.methods.append(JavaMethod(body, self))

                    # Process class fields
                    elif body.type == 'field_declaration':
                        field_name = None
                        type_node = body.child_by_field_name('type')
                        if not type_node or not type_node.text:
                            continue

                        field_type = type_node.text.decode()
                        fields = [
                            field for field in body.children
                            if field.type == 'variable_declarator'
                        ]
                        for field in fields:
                            # Process field_name
                            self.constructor_callsites.append(field)
                            name_node = field.child_by_field_name('name')

                        if name_node and name_node.text and field_type:
                            field_name = name_node.text.decode()
                            self.class_fields[field_name] = field_type

                    # Process inner classes or interfaces
                    elif body.type in [
                            'class_declaration', 'interface_declaration'
                    ]:
                        inner_class_nodes.append(body)

        return inner_class_nodes

    def _process_inner_classes(self, inner_class_nodes: list[Node]):
        """Internal helper to recursively process inner classes"""
        for node in inner_class_nodes:
            self.inner_classes.append(
                JavaClassInterface(node, self.tree_sitter_lang,
                                   self.parent_source, self))

    def _has_constructor_defined(self) -> bool:
        """Helper method to determine if any constructor is defined."""
        for method in self.methods:
            if method.is_constructor:
                return True

        return False

    def get_all_methods(self) -> list[JavaMethod]:
        all_methods = self.methods
        for inner_class in self.inner_classes:
            all_methods.extend(inner_class.get_all_methods())

        return all_methods

    def get_entry_method_name(self) -> Optional[str]:
        """Get the entry method name for this class.
        It can be the provided entrypoint or method with
        @FuzzTest annotation."""
        for method in self.get_all_methods():
            if method.is_entry_method:
                return method.name

        return None

    def has_libfuzzer_harness(self) -> bool:
        """Returns whether the source code holds a libfuzzer harness"""
        if any(method.is_entry_method for method in self.get_all_methods()):
            return True

        return False

    def has_method_definition(
            self,
            target_name: str,
            partial_match: bool = False) -> tuple[bool, Optional[JavaMethod]]:
        """Returns if the source file holds a given function definition.
        Also return the matching method object if found."""
        for method in self.get_all_methods():
            method_name = method.name
            if partial_match:
                target_name = target_name.split('(')[0]
                method_name = method_name.split('(')[0]

            if method_name == target_name:
                return True, method

        return False, None


class JvmProject(Project[JvmSourceCodeFile]):
    """Wrapper for doing analysis of a collection of source files."""

    def __init__(self, source_code_files: list[JvmSourceCodeFile]):
        super().__init__(source_code_files)
        self.all_classes = []
        for source_code in self.source_code_files:
            self.all_classes.extend(source_code.classes)

    def dump_module_logic(self,
                          report_name: str,
                          entry_function: str = '',
                          harness_name: str = '',
                          harness_source: str = '',
                          dump_output: bool = True):
        """Dumps the data for the module in full."""
        logger.info('Dumping project-wide logic.')
        report: dict[str, Any] = {'report': 'name'}
        report['sources'] = []
        report['Fuzzer filename'] = harness_source

        all_classes = {}
        project_methods: list[JavaMethod] = []

        # Post process source code files with full qualified names
        # Retrieve full project methods, classes and information
        for source_code in self.source_code_files:
            # Post process source code imports
            source_code.post_process_imports(self.all_classes)

            # Retrieve list of class and post process them
            for cls in source_code.classes:
                cls.post_process_full_qualified_name()
                all_classes[cls.name] = cls

            # Log entry method if provided
            if harness_name and source_code.has_class(harness_name):
                entry_func = source_code.get_entry_method_name(True)
                if entry_func:
                    report['Fuzzing method'] = entry_func

            # Retrieve full proejct methods and information
            methods = source_code.get_all_methods()
            report['sources'].append({
                'source_file': source_code.source_file,
                'function_names': list(methods.keys()),
            })
            project_methods.extend(methods.values())

        # Extract callsites of methods
        for method in project_methods:
            method.extract_callsites(all_classes)

        # Process all project methods
        method_list = []
        for method in project_methods:
            method_dict: dict[str, Any] = {}

            if method.parent_source:
                method_dict[
                    'functionSourceFile'] = method.parent_source.source_file
            else:
                method_dict['functionSourceFile'] = method.class_interface.name

            method_dict['functionName'] = method.name
            method_dict['functionLinenumber'] = method.start_line
            method_dict['functionLinenumberEnd'] = method.end_line
            method_dict['linkageType'] = ''
            method_dict['func_position'] = {
                'start': method.start_line,
                'end': method.end_line
            }
            method_dict['CyclomaticComplexity'] = method.complexity
            method_dict['EdgeCount'] = method_dict['CyclomaticComplexity']
            method_dict['ICount'] = method.icount
            method_dict['argNames'] = method.arg_names
            method_dict['argTypes'] = method.arg_types[:]
            method_dict['argCount'] = len(method_dict['argTypes'])
            method_dict['returnType'] = method.return_type
            method_dict['BranchProfiles'] = []
            method_dict['Callsites'] = method.detailed_callsites
            method_dict['functionUses'] = self.calculate_method_uses(
                method.name, project_methods)
            method_dict['functionDepth'] = self.calculate_method_depth(
                method, project_methods)
            method_dict['constantsTouched'] = []
            method_dict['BBCount'] = 0
            method_dict['signature'] = method.name
            callsites = method.base_callsites
            reached = set()
            for cs_dst, _ in callsites:
                reached.add(cs_dst)
            method_dict['functionsReached'] = list(reached)

            # Handles Java method properties
            java_method_info: dict[str, Any] = {}
            java_method_info['exceptions'] = method.exceptions
            java_method_info[
                'interfaces'] = method.class_interface.super_interfaces[:]
            java_method_info['classFields'] = list(
                method.class_interface.class_fields.values())
            java_method_info['argumentGenericTypes'] = method.arg_types[:]
            java_method_info['returnValueGenericType'] = method.return_type
            java_method_info['superClass'] = method.class_interface.super_class
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

        if dump_output:
            with open(report_name, 'w', encoding='utf-8') as f:
                f.write(yaml.dump(report))

    def find_source_with_method(self,
                                name: str) -> Optional[JvmSourceCodeFile]:
        """Finds the source code with a given method name."""
        for source_code in self.source_code_files:
            if source_code.has_method_definition(name):
                return source_code

        return None

    def calculate_method_uses(self, target_name: str,
                              all_methods: list[JavaMethod]) -> int:
        """Calculate how many method called the target method."""
        method_use_count = 0
        for method in all_methods:
            found = False
            for callsite in method.base_callsites:
                if callsite[0] == target_name:
                    found = True
                    break
            if found:
                method_use_count += 1

        return method_use_count

    def calculate_method_depth(self, target_method: JavaMethod,
                               all_methods: list[JavaMethod]) -> int:
        """Calculate method depth of the target method."""

        def _recursive_method_depth(method: JavaMethod) -> int:
            callsites = method.base_callsites
            if len(callsites) == 0:
                return 0

            depth = 0
            visited.append(method.name)
            for callsite in callsites:
                target = method_dict.get(callsite[0])
                if callsite[0] in visited:
                    depth = max(depth, 1)
                elif target:
                    depth = max(depth, _recursive_method_depth(target) + 1)
                else:
                    visited.append(callsite[0])

            return depth

        visited: list[str] = []
        method_dict = {method.name: method for method in all_methods}
        method_depth = _recursive_method_depth(target_method)

        return method_depth

    def extract_calltree(self,
                         source_file: str = '',
                         source_code: Optional[JvmSourceCodeFile] = None,
                         function: Optional[str] = None,
                         visited_functions: Optional[set[str]] = None,
                         depth: int = 0,
                         line_number: int = -1,
                         other_props: Optional[dict[str, Any]] = None) -> str:
        """Extracts calltree string of a calltree so that FI core can use it."""
        if not visited_functions:
            visited_functions = set()

        if function and '].' not in function:
            function = None

        if not source_code and function:
            source_code = self.find_source_with_method(function)

        if not function and source_code:
            function = source_code.get_entry_method_name(True)

        if not function:
            return ''

        line_to_print = '  ' * depth
        line_to_print += function
        line_to_print += ' '
        line_to_print += source_file
        line_to_print += ' '
        line_to_print += str(line_number)
        line_to_print += '\n'

        if not source_code:
            return line_to_print

        function_node = source_code.get_method_node(function)
        if not function_node:
            return line_to_print

        callsites = function_node.base_callsites

        if function in visited_functions:
            return line_to_print

        visited_functions.add(function)
        for cs, line in callsites:
            line_to_print += self.extract_calltree(
                source_code.source_file,
                function=cs,
                visited_functions=visited_functions,
                depth=depth + 1,
                line_number=line)

        return line_to_print

    def get_source_codes_with_harnesses(self) -> list[JvmSourceCodeFile]:
        return super().get_source_codes_with_harnesses()

    def get_reachable_functions(
            self,
            source_file: str = '',
            source_code: Optional[JvmSourceCodeFile] = None,
            function: Optional[str] = None,
            visited_functions: Optional[set[str]] = None) -> set[str]:
        """Get a list of reachable functions for a provided function name."""
        if not visited_functions:
            visited_functions = set()

        if not source_code and function:
            source_code = self.find_source_with_method(function)

        if not function and source_code:
            function = source_code.get_entry_method_name(True)

        if source_code and function:
            function_node = source_code.get_method_node(function)
            if not function_node:
                visited_functions.add(function)
                return visited_functions
        else:
            if function:
                visited_functions.add(function)
            return visited_functions

        visited_functions.add(function)
        for cs, _ in function_node.base_callsites:
            if cs in visited_functions:
                continue

            visited_functions = self.get_reachable_functions(
                source_code.source_file,
                function=cs,
                visited_functions=visited_functions)

        return visited_functions


def load_treesitter_trees(source_files: list[str],
                          entrypoint: str,
                          is_log: bool = True) -> JvmProject:
    """Creates treesitter trees for all files in a given list of
    source files."""
    results = []

    for code_file in source_files:
        source_cls = JvmSourceCodeFile('jvm', code_file, entrypoint)
        if is_log:
            if source_cls.has_libfuzzer_harness():
                logger.info('harness: %s', code_file)
        results.append(source_cls)

    return JvmProject(results)


def analyse_source_code(source_content: str) -> JvmSourceCodeFile:
    """Returns a source abstraction based on a single source string."""
    source_code = JvmSourceCodeFile('jvm',
                                    source_file='in-memory string',
                                    source_content=source_content.encode())
    return source_code
