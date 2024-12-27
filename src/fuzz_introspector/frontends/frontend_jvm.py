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

from typing import Optional

import os
import pathlib
import logging

from tree_sitter import Language, Parser, Node
import tree_sitter_java
import yaml

from typing import Any

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


class SourceCodeFile():
    """Class for holding file-specific information."""

    def __init__(self,
                 source_file: str,
                 entrypoint: str = 'fuzzerTestOneInput',
                 source_content: Optional[bytes] = None):
        logger.info('Processing %s' % source_file)

        self.root = None
        self.source_file = source_file
        self.entrypoint = entrypoint
        self.tree_sitter_lang = Language(tree_sitter_java.language())
        self.parser = Parser(self.tree_sitter_lang)

        if source_content:
            self.source_content = source_content
        else:
            with open(self.source_file, 'rb') as f:
                self.source_content = f.read()

        # List of definitions in the source file.
        self.package = ''
        self.classes = []
        self.imports = {}

        # Initialization ruotines
        self.load_tree()

        # Load package declaration
        self._set_package_declaration()

        # Load classes/interfaces delcaration
        self._set_class_interface_declaration()

        # Load import statements
        self._set_import_declaration()

    def load_tree(self):
        """Load the the source code into a treesitter tree, and set
        the root node."""
        self.root = self.parser.parse(self.source_content).root_node

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
                    if package.type == 'scoped_identifier':
                        self.package = package.text.decode()

    def _set_class_interface_declaration(self):
        """Internal helper for retrieving all classes."""
        for node in self.root.children:
            if node.type == 'class_declaration' or node.type == 'interface_declaration':
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
                 is_constructor: bool = False):
        self.root = root
        self.class_interface = class_interface
        self.tree_sitter_lang = self.class_interface.tree_sitter_lang
        self.parent_source = self.class_interface.parent_source
        self.is_constructor = is_constructor

        # Store method line information
        self.start_line = self.root.start_point.row + 1
        self.end_line = self.root.end_point.row + 1

        # Other properties
        self.name = ''
        self.complexity = 0
        self.icount = 0
        self.arg_names = []
        self.arg_types = []
        self.exceptions = []
        self.return_type = ''
        self.sig = ''
        self.function_uses = 0
        self.function_depth = 0
        self.base_callsites = []
        self.detailed_callsites = []
        self.public = False
        self.concrete = True
        self.static = False
        self.is_entry_method = False

        # Other properties
        self.stmts = []
        self.var_map = {}

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
        self.name = f'[{class_name}].{self.name}({",".join(self.arg_types)})'

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
            elif child.type == 'type_identifier' or child.type.endswith(
                    '_type'):
                self.return_type = child.text.decode()

            # Process body and store statment nodes
            elif child.type == 'block' or child.type == 'constructor_body':
                for stmt in child.children:
                    if stmt.type not in ['{', '}'
                                         ] and 'comment' not in stmt.type:
                        self.stmts.append(stmt)

            # Process exceptions
            elif child.type == 'throws':
                for exception in child.children:
                    if exception.type == 'type_identifier':
                        self.exceptions.append(exception.text.decode())

    def _process_statements(self):
        """Loop through all statements and process them."""
        for stmt in self.stmts:
            self._process_complexity(stmt)
            self._process_icount(stmt)
            self._process_variable_declaration(stmt)

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

    def _process_variable_declaration(self, stmt: Node):
        """Process the local variable declaration."""
        variable_type = None
        variable_name = None

        if stmt.type == 'local_variable_declaration':
            variable_type = stmt.child_by_field_name('type').text.decode()
            for vars in stmt.children:
                if vars.type == 'variable_declarator':
                    variable_name = vars.child_by_field_name(
                        'name').text.decode()

        if variable_type and variable_name:
            self.var_map[variable_name] = variable_type

    def _process_invoke_object(
        self, stmt: Node, classes: dict[str, 'JavaClassInterface']
    ) -> tuple[str, list[tuple[str, int, int]]]:
        """Internal helper for processing the object from a invocation."""
        callsites = []
        return_value = ''
        # Determine the type of the object
        if stmt.child_count == 0:
            # Class call
            if stmt.type == 'this':
                return_value = self.class_interface.name

            # SuperClass call
            elif stmt.type == 'super':
                return_value = self.class_interface.super_class

            # Variable call or static call
            else:
                return_value = self.var_map.get(stmt.text.decode(), '')
                if not return_value:
                    return_value = self.class_interface.class_fields.get(
                        stmt.text.decode(), '')
                if not return_value:
                    return_value = self.parent_source.imports.get(
                        stmt.text.decode(), self.class_interface.name)
        else:
            # Field access
            if stmt.type == 'field_access':
                object = stmt.child_by_field_name('object')
                field = stmt.child_by_field_name('field')

                if object and field:
                    object_class, callsites = self._process_invoke_object(
                        object, classes)
                    cls = classes.get(object_class)
                    if cls:
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
                    if cast.type == 'cast_expression':
                        value = cast.child_by_field_name('value')
                        cast_type = cast.child_by_field_name(
                            'type').text.decode()
                        return_value = self.parent_source.get_full_qualified_name(
                            cast_type)
                        if value and value.type == 'method_invocation':
                            _, invoke_callsites = self._process_invoke(
                                value, classes)
                            callsites.extend(invoke_callsites)
                        if value and value.type == 'object_creation_expression':
                            _, invoke_callsites = self._process_invoke(
                                value, classes, True)
                            callsites.extend(invoke_callsites)
                        if value and value.type == 'explicit_constructor_invocation':
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

            # Variables
            if argument.type == 'identifier':
                return_value = self.var_map.get(argument.text.decode(), '')
                if not return_value:
                    return_value = self.class_interface.class_fields.get(
                        argument.text.decode(), self.class_interface.name)
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
                object = argument.child_by_field_name('object')
                field = argument.child_by_field_name('field')

                if object and field:
                    object_class, callsites = self._process_invoke_object(
                        object, classes)
                    cls = classes.get(object_class)
                    if cls:
                        return_value = cls.class_fields.get(
                            field.text.decode(), self.class_interface.name)
                return_values.append(return_value)

            # Type casting expression
            elif argument.type == 'cast_expression':
                value = argument.child_by_field_name('value')
                cast_type = argument.child_by_field_name('type').text.decode()
                return_value = self.parent_source.get_full_qualified_name(
                    cast_type)
                if value and value.type == 'method_invocation':
                    _, invoke_callsites = self._process_invoke(value, classes)
                    callsites.extend(invoke_callsites)
                if value and value.type == 'object_creation_expression':
                    _, invoke_callsites = self._process_invoke(
                        value, classes, True)
                    callsites.extend(invoke_callsites)
                if value and value.type == 'explicit_constructor_invocation':
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
    ) -> tuple[list[str], list[tuple[str, int, int]]]:
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
        if is_constructor_call:
            object_type = ''
            for cls_type in expr.children:
                if cls_type.type == 'this':
                    object_type = self.class_interface.name

                elif cls_type.type == 'super':
                    object_type = self.class_interface.super_class

                elif cls_type.type == 'type_identifier' or cls_type.type.endswith(
                        '_type'):
                    object_type = cls_type.text.decode().split('<')[0]

            object_type = self.parent_source.get_full_qualified_name(
                object_type)
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
        if object_type and name:
            target_name = f'[{object_type}].{name.text.decode()}({",".join(argument_types)})'
            callsites.append(
                (target_name, expr.byte_range[1], expr.start_point.row + 1))

        # Determine return value from method invocation
        if object_type == 'com.code_intelligence.jazzer.api.FuzzedDataProvider':
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
        self, stmt: Node,
        classes: dict[str,
                      'JavaClassInterface']) -> list[tuple[str, int, int]]:
        """Process and store the callsites of the method."""
        callsites = []

        if stmt.type == 'method_invocation':
            _, invoke_callsites = self._process_invoke(stmt, classes)
            callsites.extend(invoke_callsites)
        elif stmt.type == 'object_creation_expression':
            _, invoke_callsites = self._process_invoke(stmt, classes, True)
            callsites.extend(invoke_callsites)
        elif stmt.type == 'explicit_constructor_invocation':
            _, invoke_callsites = self._process_invoke(stmt, classes, True)
            callsites.extend(invoke_callsites)
        else:
            for child in stmt.children:
                callsites.extend(self._process_callsites(child, classes))

        return callsites

    def extract_callsites(self, classes: dict[str, 'JavaClassInterface']):
        """Extract callsites."""

        if not self.base_callsites:
            callsites = []
            for stmt in self.stmts:
                callsites.extend(self._process_callsites(stmt, classes))
            callsites = sorted(set(callsites), key=lambda x: x[1])
            self.base_callsites = [(x[0], x[2]) for x in callsites]

        if not self.detailed_callsites:
            for dst, src_line in self.base_callsites:
                src_loc = self.class_interface.name + ':%d,1' % (src_line)
                self.detailed_callsites.append({'Src': src_loc, 'Dst': dst})


class JavaClassInterface():
    """Wrapper for a General Declaration for java classes"""

    def __init__(self,
                 root: Node,
                 tree_sitter_lang: Optional[Language] = None,
                 source_code: Optional[SourceCodeFile] = None,
                 parent: Optional['JavaClassInterface'] = None):
        self.root = root
        self.parent = parent

        if parent:
            self.tree_sitter_lang = parent.tree_sitter_lang
            self.parent_source = parent.parent_source
            self.package = self.parent.name
        else:
            self.tree_sitter_lang = tree_sitter_lang
            self.parent_source = source_code
            self.package = self.parent_source.package

        # Properties
        self.name = ''
        self.class_public = False
        self.class_concrete = True
        self.is_interface = False
        self.methods = []
        self.inner_classes = []
        self.class_fields = {}
        self.super_class = 'Object'
        self.super_interfaces = []

        # Process the class/interface tree
        inner_class_nodes = self._process_node()

        # Process inner classes
        self._process_inner_classes(inner_class_nodes)

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
                    if cls.type == 'type_identifier':
                        self.super_class = cls.text.decode()

            # Process super interfaces
            elif child.type == 'super_interfaces':
                for interfaces in child.children:
                    if interfaces.type == 'type_list':
                        type_set = set()
                        for interface in interfaces.children:
                            if interface.type == 'type_identifier':
                                type_set.add(interface.text.decode())
                        self.super_interfaces = list(type_set)

            # Process modifiers
            elif child.type == 'modifiers':
                for modifier in child.children:
                    if modifier.text.decode() == 'public':
                        self.class_public = True
                    if modifier.text.decode() == 'abstract':
                        self.class_concrete = False

            # Process modifiers for interface
            elif child.type == 'interface':
                self.is_interface = True
                self.class_concrete = False

            # Process name
            elif child.type == 'identifier':
                self.name = child.text.decode()
                if self.package:
                    self.name = f'{self.package}.{self.name}'

            # Process body
            elif child.type == 'class_body' or child.type == 'interface_body':
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
                        field_type = body.child_by_field_name(
                            'type').text.decode()
                        for fields in body.children:
                            # Process field_name
                            if fields.type == 'variable_declarator':
                                field_name = fields.child_by_field_name(
                                    'name').text.decode()

                        if field_name and field_type:
                            self.class_fields[field_name] = field_type

                    # Process inner classes or interfaces
                    elif body.type == 'class_declaration' or body.type == 'interface_declaration':
                        inner_class_nodes.append(body)

        return inner_class_nodes

    def _process_inner_classes(self, inner_class_nodes: list[Node]):
        """Internal helper to recursively process inner classes"""
        for node in inner_class_nodes:
            self.inner_classes.append(
                JavaClassInterface(node, None, None, self))

    def get_all_methods(self) -> list[JavaMethod]:
        all_methods = self.methods
        for inner_class in self.inner_classes:
            all_methods.extend(inner_class.get_all_methods())

        return all_methods

    def get_entry_method_name(self) -> Optional[str]:
        """Get the entry method name for this class.
        It can be the provided entrypoint of method with @FuzzTest annotation."""
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


class Project():
    """Wrapper for doing analysis of a collection of source files."""

    def __init__(self, source_code_files: list[SourceCodeFile]):
        self.source_code_files = source_code_files
        self.all_classes = []
        for source_code in self.source_code_files:
            self.all_classes.extend(source_code.classes)

    def dump_module_logic(self,
                          report_name: str,
                          harness_name: Optional[str] = None):
        """Dumps the data for the module in full."""
        logger.info('Dumping project-wide logic.')
        report = {'report': 'name'}
        report['sources']: dict[str, Any] = []

        all_classes = {}
        project_methods = []

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
                entry_method = source_code.get_entry_method_name(True)
                if entry_method:
                    report['Fuzzing method'] = entry_method

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
            method_dict = {}
            method_dict['functionName'] = method.name
            method_dict['functionSourceFile'] = method.class_interface.name
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
            java_method_info = {}
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

        with open(report_name, 'w', encoding='utf-8') as f:
            f.write(yaml.dump(report))

    def get_source_codes_with_harnesses(self) -> list[SourceCodeFile]:
        """Gets the source codes that holds libfuzzer harnesses."""
        harnesses = []
        for source_code in self.source_code_files:
            if source_code.has_libfuzzer_harness():
                harnesses.append(source_code)

        return harnesses

    def find_source_with_method(self, name: str) -> Optional[SourceCodeFile]:
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

        visited = []
        method_dict = {method.name: method for method in all_methods}
        method_depth = _recursive_method_depth(target_method)

        return method_depth

    def extract_calltree(self,
                         source_file: str,
                         source_code: Optional[SourceCodeFile] = None,
                         method: str = None,
                         visited_methods: set[str] = None,
                         depth: int = 0,
                         line_number: int = -1) -> str:
        """Extracts calltree string of a calltree so that FI core can use it."""
        if not visited_methods:
            visited_methods = set()

        if not method:
            method = source_code.get_entry_method_name(True)

        line_to_print = '  ' * depth
        line_to_print += method
        line_to_print += ' '
        line_to_print += source_file

        if not source_code:
            source_code = self.find_source_with_method(method)

        line_to_print += ' '
        line_to_print += str(line_number)

        line_to_print += '\n'
        if not source_code:
            return line_to_print

        method = source_code.get_method_node(method)
        if not method:
            return line_to_print

        callsites = method.base_callsites

        if method in visited_methods:
            return line_to_print

        visited_methods.add(method)
        for cs, line_number in callsites:
            line_to_print += self.extract_calltree(
                source_code.source_file,
                method=cs,
                visited_methods=visited_methods,
                depth=depth + 1,
                line_number=line_number)
        return line_to_print


def capture_source_files_in_tree(directory_tree: str) -> list[str]:
    """Captures source code files in a given directory."""
    exclude_directories = [
        'target', 'test', 'node_modules', 'aflplusplus', 'honggfuzz',
        'inspector', 'libfuzzer'
    ]
    language_extensions = ['.java']
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
                          entrypoint: str,
                          is_log: bool = True) -> list[SourceCodeFile]:
    """Creates treesitter trees for all files in a given list of source files."""
    results = []

    for code_file in source_files:
        source_cls = SourceCodeFile(code_file, entrypoint)
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
