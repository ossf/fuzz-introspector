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

from typing import Optional

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
        self._set_function_method_declaration()

        print(f'{source_file}:{len(self.functions)}')

    def load_tree(self):
        """Load the the source code into a treesitter tree, and set
        the root node."""
        self.root = self.parser.parse(self.source_content).root_node

    def _set_function_method_declaration(self):
        """Internal helper for retrieving all classes."""
        for node in self.root.children:

            # Handle general functions
            if node.type == 'function_item':
                self.functions.append(
                    RustFunction(node, self.tree_sitter_lang, self))

            # Handle impl methods
            elif node.type == 'impl_item':
                impl_body = node.child_by_field_name('body')
                for impl in impl_body.children:
                    if impl.type == 'function_item':
                        self.functions.append(
                            RustFunction(impl, self.tree_sitter_lang, self, node))

            # Handle mod functions
            elif node.type == 'mod_item':
                mod_body = node.child_by_field_name('body')
                if mod_body:
                    for mod in mod_body.children:
                        if mod.type == 'function_item':
                            self.functions.append(
                                RustFunction(mod, self.tree_sitter_lang, self, mod=node))

            # Handling for fuzzing harness entry point macro invocation
            elif node.type == 'expression_statement':
                for macro in node.children:
                    if macro.type == 'macro_invocation':
                        rust_function = RustFunction(
                            macro, self.tree_sitter_lang, self, is_macro=True)

                        # Only consider the macro as function if it is the
                        # fuzzing entry point (fuzz_target macro)
                        if rust_function.is_entry_method:
                            self.functions.append(rust_function)

    def has_libfuzzer_harness(self) -> bool:
        """Returns whether the source code holds a libfuzzer harness"""
        if any(func.is_entry_method for func in self.functions):
            return True

        return False


class RustFunction():
    """Wrapper for a General Declaration for function"""

    def __init__(self,
                 root: Node,
                 tree_sitter_lang: Optional[Language] = None,
                 source_code: Optional[SourceCodeFile] = None,
                 impl: Optional[Node] = None,
                 mod: Optional[Node] = None,
                 is_macro: bool = False):
        self.root = root
        self.tree_sitter_lang = tree_sitter_lang
        self.parent_source = source_code
        self.impl = impl
        self.mod = mod
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

        # Process method declaration
        if is_macro:
            self._process_macro_declaration()
        else:
            self._process_declaration()

    def _process_declaration(self):
        """Internal helper to process the function/method declaration."""
        for child in self.root.children:
            # Process name
            if child.type == 'identifier':
                self.name = child.text.decode()

    def _process_macro_declaration(self):
        """Internal helper to process the macro declaration for fuzzing
        entry point."""
        for child in self.root.children:
            # Process name
            if child.type == 'identifier':
                self.name = child.text.decode()
                if self.name == 'fuzz_target':
                    self.is_entry_method = True

            # token_tree for body


def capture_source_files_in_tree(directory_tree: str) -> list[str]:
    """Captures source code files in a given directory."""
    exclude_directories = [
        'tests', 'examples', 'benches', 'node_modules',
        'aflplusplus', 'honggfuzz', 'inspector', 'libfuzzer'
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
