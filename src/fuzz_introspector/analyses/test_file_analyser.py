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
"""Analysis plugin for analysing test files."""
import json
import logging
import os

from typing import (Any, List, Dict)

from fuzz_introspector import (analysis, html_helpers)

from fuzz_introspector.datatypes import (project_profile, fuzzer_profile)

logger = logging.getLogger(name=__name__)


class TestFileAnalyser(analysis.AnalysisInterface):
    """Analysis utility for testing analysis."""

    name: str = 'TestFileAnalyser'

    def __init__(self) -> None:
        self.json_results: Dict[str, Any] = {}
        self.json_string_result = ''
        self.directory = ''
        self.language = ''

    @classmethod
    def get_name(cls):
        """Return the analyser identifying name for processing.

        :return: The identifying name of this analyser
        :rtype: str
        """
        return cls.name

    def get_json_string_result(self) -> str:
        """Return the stored json string result.

        :return: The json string result processed and stored
            by this analyser
        :rtype: str
        """
        if self.json_string_result:
            return self.json_string_result

        return json.dumps(self.json_results)

    def set_json_string_result(self, json_string: str):
        """Store the result of this analyser as json string result
        for further processing in a later time.

        :param json_string: A json string variable storing the
            processing result of the analyser for future use
        :type json_string: str
        """
        self.json_string_result = json_string

    def set_base_information(self, directory: str, language: str):
        """Setter for base information."""
        self.directory = os.path.abspath(directory)
        self.language = language

    def analysis_func(self,
                      table_of_contents: html_helpers.HtmlTableOfContents,
                      tables: List[str],
                      proj_profile: project_profile.MergedProjectProfile,
                      profiles: List[fuzzer_profile.FuzzerProfile],
                      basefolder: str, coverage_url: str,
                      conclusions: List[html_helpers.HTMLConclusion],
                      out_dir: str) -> str:
        """Analysis function."""
        self.standalone_analysis(proj_profile, profiles, out_dir)
        return ''

    def standalone_analysis(self,
                            proj_profile: project_profile.MergedProjectProfile,
                            profiles: List[fuzzer_profile.FuzzerProfile],
                            out_dir: str) -> None:
        """Standalone analysis."""
        super().standalone_analysis(proj_profile, profiles, out_dir)
        functions = proj_profile.get_all_functions_with_source()

        test_files = set()
        if os.path.isfile(os.path.join(out_dir, 'all_tests.json')):
            with open(os.path.join(out_dir, 'all_tests.json'), 'r') as f:
                test_files = set(json.load(f))

        # Auto determine base information if not provided
        if not self.directory:
            paths = [func.function_source_file for func in functions.values()]
            self.directory = os.path.commonpath(paths)

        if not self.language:
            self.language = proj_profile.language

        test_files.update(analysis.extract_tests_from_directories(
            {self.directory}, self.language, out_dir, False))

        # Get all functions within test files
        test_functions: dict[str, list[dict[str, object]]] = {}
        seen_functions: dict[str, set[tuple[str, str]]] = {}
        for function in functions.values():
            test_source = function.function_source_file

            # Skip unrelated functions
            if test_source not in test_files:
                continue

            if test_source not in test_functions:
                test_functions[test_source] = []
                seen_functions[test_source] = set()

            for reached_name in function.functions_reached:
                reached = functions.get(reached_name)

                # Skip other test functions or external functions
                if not reached or reached.function_source_file in test_files:
                    continue

                key = (reached.function_name, reached.function_source_file)

                # Skip duplicated, reached funcitons
                if key in seen_functions[test_source]:
                    continue

                seen_functions[test_source].add(key)
                test_functions[test_source].append(reached.to_dict())

        # Remove useless test files
        test_functions = {k: v for k, v in test_functions.items() if v}

        # Store test files
        with open(os.path.join(out_dir, 'all_tests.json'), 'w') as f:
            f.write(json.dumps(list(test_files)))

        # Store test files with cross reference information
        with open(os.path.join(out_dir, 'all_tests_with_xreference.json'), 'w') as f:
            f.write(json.dumps(test_functions))

        return None
