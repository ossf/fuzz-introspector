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

from typing import Any, Optional


class Project():
    """Wrapper for doing analysis of a collection of source files."""

    def __init__(self, source_code_files: list[Any]):
        self.source_code_files = source_code_files

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
                         source_code: Optional[Any] = None,
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
            source_code: Optional[Any] = None,
            function: Optional[str] = None,
            visited_functions: Optional[set[str]] = None) -> set[str]:
        """Get a list of reachable functions for a provided function name."""
        # Dummy function for subclasses
        return set()

    def get_source_codes_with_harnesses(self) -> list[Any]:
        """Gets the source codes that holds libfuzzer harnesses."""
        harnesses = []
        for source_code in self.source_code_files:
            if source_code.has_libfuzzer_harness():
                harnesses.append(source_code)

        return harnesses
