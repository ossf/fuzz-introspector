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
import tree_sitter_cpp
import tree_sitter_go
import tree_sitter_java
import tree_sitter_rust

import copy
import json
import logging
import yaml

logger = logging.getLogger(name=__name__)

T = TypeVar('T', bound='SourceCodeFile')


class SourceCodeFile():
    """Class for holding file-specific information."""
    LANGUAGE: dict[str, Language] = {
        'c': Language(tree_sitter_cpp.language()),
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
        logger.debug('Processing %s', source_file)

        self.source_file = source_file
        self.language = language
        self.entrypoint = entrypoint
        self.tree_sitter_lang = self.LANGUAGE.get(language,
                                                  self.LANGUAGE['cpp'])
        self.parser = Parser(self.tree_sitter_lang)
        self.full_type_defs: list[dict[str, Any]] = []
        self.macro_blocks: list[dict[str, Any]] = []

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
        self.root = self.parser.parse(self.source_content).root_node

    def language_specific_process(self):
        """Dummy function to perform some specific processes in subclasses."""
        pass

    def get_entry_function_name(self) -> str:
        """Dummy function for getting the entry function name."""
        return ''

    def has_libfuzzer_harness(self) -> bool:
        """Dummy function for source code files."""
        return False


class Project(Generic[T]):
    """Wrapper for doing analysis of a collection of source files."""

    def __init__(self, source_code_files: list[T]):
        self.report: dict[str, Any] = {}
        self.source_code_files = source_code_files
        self.all_functions: list[Any] = []

    def generate_report(self,
                        entry_function: str = '',
                        harness_name: str = '',
                        harness_source: str = '') -> None:
        """Helper function for generating yaml function report."""
        return

    def get_report(self,
                   entry_function: str = '',
                   harness_name: str = '',
                   harness_source: str = '') -> dict[str, Any]:
        """Runs analysis if needed and gets a report yaml"""
        self.generate_report(entry_function, harness_name, harness_source)

        new_report = copy.deepcopy(self.report)
        new_report['Fuzzer filename'] = harness_source

        return new_report

    def dump_type_definition(self,
                             report_name: str = '',
                             dump_output: bool = True) -> None:
        """Dumps the type definition for this project if exists."""
        result = []
        for source_code in self.source_code_files:
            result.extend(source_code.full_type_defs)

        if not result or not dump_output:
            return

        logger.info('Dumping custom type definitions.')
        with open(report_name, 'w', encoding='utf-8') as f:
            f.write(json.dumps(result))
        logger.info('Custom type definitions dumping completed.')

    def dump_macro_block_info(self,
                              report_name: str = '',
                              dump_output: bool = True) -> None:
        """Dumps the macro block information for this project if exists."""
        result = []
        for source_code in self.source_code_files:
            result.extend(source_code.macro_blocks)

        if not result or not dump_output:
            return

        logger.info('Dumping macro blocks information.')
        with open(report_name, 'w', encoding='utf-8') as f:
            f.write(json.dumps(result))
        logger.info('Macro blocks information dumping completed.')

    def dump_module_logic(self,
                          report_name: str = '',
                          entry_function: str = '',
                          harness_name: str = '',
                          harness_source: str = '',
                          dump_output: bool = True) -> None:
        """Dumps the data for the module in full."""
        logger.info('Generating report')
        self.generate_report(entry_function, harness_name, harness_source)
        logger.info('Report generated')
        new_report = copy.deepcopy(self.report)
        new_report['Fuzzer filename'] = harness_source

        logger.info('Dumping project-wide logic.')
        try:
            yaml.SafeDumper = yaml.CSafeDumper  # type: ignore[assignment, misc]
            logger.info('Using safe yaml safe C dumper.')
        except Exception:
            logger.info('Using non-c dumper.')
            pass

        if dump_output:
            with open(report_name, 'w', encoding='utf-8') as f:
                f.write(yaml.safe_dump(new_report))
        logger.info('Dumped')

    def extract_calltree(self,
                         source_file: str = '',
                         source_code: Optional[SourceCodeFile] = None,
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
            source_code: Optional[SourceCodeFile] = None,
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

    def get_cross_references(self, src_func: Any) -> list[Any]:
        """Gets list of functions that reference src_func"""
        # TODO specify type after generalisation of FunctionDefinition
        xrefs = []
        for func in self.all_functions:
            if func.sig == src_func:
                continue

            for callsite in func.base_callsites:
                if callsite[0] == src_func.name:
                    xrefs.append(func)

        return xrefs

    def get_cross_references_by_name(self, function_name) -> list[Any]:
        """Get cross reference functions by a target function name."""
        xrefs = []
        for func in self.all_functions:
            for callsite in func.base_callsites:
                if callsite[0] == function_name:
                    xrefs.append(func)
        return xrefs

    def find_function_by_name(self, target_function_name, only_exact_match):
        """Helper function to find the matching function."""
        for function in self.all_functions:
            if function.name == target_function_name:
                return function

        if not only_exact_match:
            for function in self.all_functions:
                if target_function_name in function.name:
                    return function

        return None

    def get_function_by_source_suffix_line(self, target_source_file,
                                           target_source_line):
        """Helper function to find the matchin function by source
        file and source file."""
        for function in self.all_functions:
            source_file = function.parent_source.source_file
            if source_file.endswith(target_source_file):
                start_line = function.start_line
                end_line = function.end_line
                if start_line <= target_source_line <= end_line:
                    return function

        return None
