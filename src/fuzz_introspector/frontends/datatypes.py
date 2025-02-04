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
"""Datatype classes for tree-sitter frontend."""

# pylint: disable=unnecessary-pass, unused-argument

from typing import Any, Optional, Generic, TypeVar

from tree_sitter import Language, Parser
import tree_sitter_c
import tree_sitter_cpp
import tree_sitter_go
import tree_sitter_java
import tree_sitter_rust

import logging

logger = logging.getLogger(name=__name__)

T = TypeVar('T', bound='SourceCodeFile')


class SourceCodeFile():
    """Class for holding file-specific information."""
    LANGUAGE: dict[str, Language] = {
        'c': Language(tree_sitter_c.language()),
        'cpp': Language(tree_sitter_cpp.language()),
        'c++': Language(tree_sitter_cpp.language()),
        'go': Language(tree_sitter_go.language()),
        'jvm': Language(tree_sitter_java.language()),
        'rust': Language(tree_sitter_rust.language()),
    }

    def __init__(self,
                 language: str,
                 source_file: str,
                 entrypoint: str = '',
                 source_content: Optional[bytes] = None):
        logger.info('Processing %s', source_file)

        self.root = None
        self.source_file = source_file
        self.language = language
        self.entrypoint = entrypoint
        self.tree_sitter_lang = self.LANGUAGE.get(language,
                                                  self.LANGUAGE['cpp'])
        self.parser = Parser(self.tree_sitter_lang)

        if source_content:
            self.source_content = source_content
        else:
            with open(self.source_file, 'rb') as f:
                self.source_content = f.read()

        # Initialization ruotines
        self.load_tree()

        # Language specific process
        self.language_specific_process()

    def load_tree(self):
        """Load the the source code into a treesitter tree, and set
        the root node."""
        if not self.root:
            self.root = self.parser.parse(self.source_content).root_node

    def language_specific_process(self):
        """Dummy function to perform some specific processes in subclasses."""
        pass

    def has_libfuzzer_harness(self) -> bool:
        """Dummy function for source code files."""
        return False


class Project(Generic[T]):
    """Wrapper for doing analysis of a collection of source files."""

    def __init__(self, source_code_files: list[T]):
        self.source_code_files = source_code_files
        self.all_functions: list[Any] = []

    def dump_module_logic(self,
                          report_name: str,
                          entry_function: str = '',
                          harness_name: str = '',
                          harness_source: str = '',
                          dump_output: bool = True):
        """Dumps the data for the module in full."""
        # Dummy function for subclasses
        pass

    def extract_calltree(self,
                         source_file: str = '',
                         source_code: Optional[T] = None,
                         function: Optional[str] = None,
                         visited_functions: Optional[set[str]] = None,
                         depth: int = 0,
                         line_number: int = -1,
                         other_props: Optional[dict[str, Any]] = None) -> str:
        """Extracts calltree string of a calltree so that FI core can use it."""
        # Dummy function for subclasses
        return ''

    def get_reachable_functions(
            self,
            source_file: str = '',
            source_code: Optional[T] = None,
            function: Optional[str] = None,
            visited_functions: Optional[set[str]] = None) -> set[str]:
        """Get a list of reachable functions for a provided function name."""
        # Dummy function for subclasses
        return set()

    def get_source_codes_with_harnesses(self) -> list[T]:
        """Gets the source codes that holds libfuzzer harnesses."""
        harnesses = []
        for source_code in self.source_code_files:
            if source_code.has_libfuzzer_harness():
                harnesses.append(source_code)

        return harnesses
