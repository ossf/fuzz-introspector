# Copyright 2025 Fuzz Introspector Authors
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
"""Tree-sitter frontend for c or cpp projects."""

from typing import Any, Optional

from tree_sitter import Language, Node

import os
import copy
import logging

from fuzz_introspector.frontends.datatypes import SourceCodeFile, Project

logger = logging.getLogger(name=__name__)


class CppSourceCodeFile(SourceCodeFile):
    """Class for holding file-specific information."""

    def language_specific_process(self) -> None:
        """Function to perform some language specific processes in
        subclasses."""
        # Variables initialisation
        self.func_defs: list['FunctionDefinition'] = []
        self.struct_defs = []
        self.union_defs = []
        self.enum_defs = []
        self.preproc_defs = []
        self.typedefs = []
        self.includes = set()

        # Process tree
        self.process_tree(self.root)

        # Combine full type definitions
        self.process_type_defs()

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

    def process_tree(self, node: Node, namespace: str = ''):
        """Process the node from the parsed tree."""
        # TODO handles namespace for all nodes
        # TODO Add more C++ specific type defintions and macros
        for child in node.children:
            if child.type == 'function_definition':
                self._process_function_node(child, namespace)
            elif child.type == 'namespace_definition':
                # Only valid for Cpp projects
                self._process_namespace_node(child, namespace)
            elif child.type == 'enum_specifier':
                self._process_enum(child, namespace)
            elif child.type == 'preproc_def':
                self._process_macro_definition(child, namespace)
            elif child.type == 'struct_specifier':
                self._process_struct(child, namespace)
            elif child.type == 'union_specifier':
                self._process_union(child, namespace)
            elif child.type == 'type_definition':
                self._process_typedef(child, namespace)
            elif child.type == 'preproc_include':
                self._process_include(child, namespace)
            elif child.type in ['preproc_ifdef', 'preproc_if']:
                self._process_macro_block(child, namespace, [])
            else:
                self.process_tree(child, namespace)

    def process_type_defs(self) -> None:
        """Helper to gather all custom type definitions."""
        self.full_type_defs.extend(self.struct_defs)
        self.full_type_defs.extend(self.typedefs)
        self.full_type_defs.extend(self.enum_defs)
        self.full_type_defs.extend(self.union_defs)
        self.full_type_defs.extend(self.preproc_defs)

    def _process_function_node(self, node: Node, namespace: str) -> None:
        """Internal helper for processing function node."""
        self.func_defs.append(
            FunctionDefinition(node, self.tree_sitter_lang, self, namespace))

    def _process_namespace_node(self, node: Node, namespace: str) -> None:
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

    def _process_enum(self, enum: Node, namespace: str) -> None:
        """Internal helper for processing enum definition."""
        enum_name_field = enum.child_by_field_name('name')
        enum_body = enum.child_by_field_name('body')
        if not enum_name_field:
            # Skip anonymous enum
            continue
        if not enum_body:
            # Skip forward declaration
            continue

        enum_item_query = self.tree_sitter_lang.query(
            '( enumerator ) @en')
        enumerator_list = []
        for _, enumerators in enum_item_query.captures(
                enum_body).items():
            for enumerator in enumerators:
                item_dict = {}
                enum_item_name = enumerator.child_by_field_name('name')
                enum_item_value = enumerator.child_by_field_name('value')

                if not enum_item_name:
                    # Skip anonymous enum items
                    continue
                item_dict['name'] = enum_item_name.text.decode()

                if enum_item_value:
                    item_dict['value'] = enum_item_value.text.decode()

                enumerator_list.append(item_dict)

        self.enum_defs.append({
            'name': enum_name_field.text.decode(),
            'enumerators': enumerator_list,
            'item_type': 'enum',
            'pos': {
                'source_file': self.source_file,
                'line_start': enum.start_point.row,
                'line_end': enum.end_point.row,
            }
        })

    def _process_macro_definition(self, preproc: Node, namespace: str) -> None:
        """Internal helper for processing macro definition."""
        preproc_name_field = preproc.child_by_field_name('name')
        preproc_body_field = preproc.child_by_field_name('value')
        if not preproc_name_field or not preproc_body_field:
            # Skip invalid preproc definition
            continue

        self.preproc_defs.append({
            'name': preproc_name_field.text.decode(),
            'type_or_value': preproc_body_field.text.decode(),
            'item_type': 'preproc_def',
            'pos': {
                'source_file': self.source_file,
                'line_start': preproc.start_point.row,
                'line_end': preproc.end_point.row,
            }
        })

    def _process_struct(self, struct: Node, namespace: str) -> None:
        """Internal helper for processing struct definition."""
        if struct.child_by_field_name('body') is None:
            # Skip forward declaration
            continue

        # Extract name for struct or anonymous struct
        struct_name_field = struct.child_by_field_name('name')
        if struct_name_field:
            struct_name = struct.child_by_field_name('name').text.decode()
        else:
            parent = struct.parent
            declarator = None
            if parent and parent.type in ['declaration', 'type_definition']:
                declarator = parent.child_by_field_name('declarator')
            if declarator:
                struct_name = declarator.text.decode()
            else:
                # Skip anonymous struct with no name
                continue

        # Go through each of the field declarations
        fields = []
        for child in struct.child_by_field_name('body').children:
            if not child.child_by_field_name('declarator'):
                continue
            if child.type == 'field_declaration':
                child_name = child.child_by_field_name('type').text.decode()
                child_type = child.child_by_field_name('declarator').text.decode()
                fields.append({
                    'type': child.child_by_field_name('type').text.decode(),
                    'name': child.child_by_field_name('declarator').text.decode()
                })
        self.struct_defs.append({
            'name': struct_name,
            'fields': fields,
            'item_type': 'struct',
            'pos': {
                'source_file': self.source_file,
                'line_start': struct.start_point.row,
                'line_end': struct.end_point.row,
            }
        })

    def _process_union(self, union: Node, namespace: str) -> None:
        """Internal helper for processing union definition."""
        if union.child_by_field_name('body') is None:
            # Skip forward declaration
            continue

        # Extract name for union or anonymous union
        union_name_field = union.child_by_field_name('name')
        if union_name_field:
            union_name = union.child_by_field_name('name').text.decode()
        else:
            parent = union.parent
            declarator = None
            if parent and parent.type in ['declaration', 'type_definition']:
                declarator = parent.child_by_field_name('declarator')
            if declarator:
                union_name = declarator.text.decode()
            else:
                # Skip anonymous union with no name
                continue

        # Go through each of the field declarations
        fields = []
        for child in union.child_by_field_name('body').children:
            if not child.child_by_field_name('declarator'):
                continue
            if child.type == 'field_declaration':
                child_name = child.child_by_field_name('type').text.decode()
                child_type = child.child_by_field_name('declarator').text.decode()
                fields.append({
                    'type': child_name,
                    'name': child_type,
                })
        self.union_defs.append({
            'name': union_name,
            'fields': fields,
            'item_type': 'union',
            'pos': {
                'source_file': self.source_file,
                'line_start': union.start_point.row,
                'line_end': union.end_point.row,
            }
        })

    def _process_typedef(self, typedef: Node, namespace: str) -> None:
        """Internal helper for processing custom type definition."""
        # Skip if this is an anonymous type.
        typedef_declarator_node = typedef.child_by_field_name('declarator')
        if not typedef_declarator_node or not typedef_declarator_node.text:
            continue

        typedef_struct = {
            'name': typedef_declarator_node.text.decode(),
            'item_type': 'typedef',
        }

        typedef_struct['pos'] = {
            'source_file': self.source_file,
            'line_start': typedef.start_point.row,
            'line_end': typedef.end_point.row,
        }
        typedef_type = typedef.child_by_field_name('type')
        if typedef_type.type in ['struct_specifier', 'union_specifier']:
            # Already handled in the above struct/union section
            continue
        elif typedef_type.type == 'primitive_type':
            typedef_struct['type'] = typedef_type.text.decode()
        elif typedef_type.type == 'sized_type_specifier':
            typedef_struct['type'] = typedef_type.text.decode()

        self.typedefs.append(typedef_struct)

    def _process_include(self, include: Node, namespace: str) -> None:
        """Internal helper for processing include statements."""
        include_path_node = include.child_by_field_name('path')
        include_path = include_path_node.text.decode().replace(
            '"', '').replace('>', '').replace('<', '')
        self.includes.add(include_path)

    def _process_macro_block(self, macro: Node, namespace: str, conditions: list[dict[str, str]]) -> None:
        """Recursive function to process macro nodes and extract all #elif
        and #else macro sub-branches."""
        # if it is the #elif or #else branches, previous condition must be reversed.
        if conditions:
            if conditions[-1]['type'] == 'ifdef':
                conditions[-1]['type'] = 'ifndef'
            elif conditions[-1]['type'] == 'ifndef':
                conditions[-1]['type'] = 'ifdef'
            else:
                conditions[-1]['type'] = 'not'

        if macro.type == 'preproc_ifdef':
            var_name = macro.child_by_field_name('name')

            # Skip invalid macro
            if not var_name or not var_name.text:
                return

            if macro and macro.text and macro.text.decode().startswith(
                    '#ifdef'):
                type = 'ifdef'
            else:
                type = 'ifndef'
            conditions.append({
                'type': type,
                'condition': var_name.text.decode(),
            })
        elif macro.type in ['preproc_if', 'preproc_elif']:
            condition = macro.child_by_field_name('condition')

            # Skip invalid macro
            if not condition or not condition.text:
                return

            conditions.append({
                'type': 'if',
                'condition': condition.text.decode(),
            })

        # Extract #else #elif branches
        alternative = macro.child_by_field_name('alternative')

        if alternative:
            # Have #elif or #else branches
            self.macro_blocks.append({
                'conditions': conditions,
                'pos': {
                    'source_file': self.source_file,
                    'line_start': macro.start_point.row,
                    'line_end': alternative.start_point.row,
                }
            })
        else:
            # No more #elif or #else branches
            self.macro_blocks.append({
                'conditions': conditions,
                'pos': {
                    'source_file': self.source_file,
                    'line_start': macro.start_point.row,
                    'line_end': macro.end_point.row,
                }
            })
            return

        # Recursively extract more #else or #elseif branches
        self._process_macro_block(alternative, namespace, copy.deepcopy(conditions))


class CppProject(datatypes.Project[CppSourceCodeFile]):
    """Wrapper for doing analysis of a collection of source files."""

    def __init__(self, source_code_files: list[CppSourceCodeFile]):
        super().__init__(source_code_files)
        self.internal_func_list: list[dict[str, Any]] = []


class FunctionDefinition():
    """Wrapper for a function definition"""

    def __init__(self, root, tree_sitter_lang, source_code):
        self.root = root
        self.tree_sitter_lang = tree_sitter_lang
        self.parent_source = source_code


def load_treesitter_trees(source_files: list[str], is_log: bool=True) -> CppProject:
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

        if is_log:
            if source_cls.has_libfuzzer_harness():
                logger.info('harness: %s', code_file)

        results.append(source_cls)

    return CppProject(results)


def analyse_source_code(source_content: str) -> CppSourceCodeFile:
    """Returns a source abstraction based on a single source string."""
    source_code = CppSourceCodeFile('c++',
                                    source_file='in-memory string',
                                    source_content=source_content.encode())
    return source_code
