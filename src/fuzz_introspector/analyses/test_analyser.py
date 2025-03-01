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
"""Analysis plugin for analysing tests."""
import json
import logging

from typing import (Any, List, Dict)

from fuzz_introspector import (analysis, html_helpers)

from fuzz_introspector.datatypes import (project_profile, fuzzer_profile)

logger = logging.getLogger(name=__name__)


class TestAnalyser(analysis.AnalysisInterface):
    """Analysis utility for testing analysis."""

    name: str = 'TestAnalyser'

    def __init__(self) -> None:
        self.json_results: Dict[str, Any] = {}
        self.json_string_result = ''
        self.test_file_paths = set()

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

    def set_flags(self):
        """Configure the flags from the CLI."""
        return

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

        # Get all functions from the profiles
        all_functions = list(proj_profile.all_functions.values())
        all_functions.extend(proj_profile.all_constructors.values())

        for function in all_functions:
            if 'test' in function.function_source_file:
                logger.info('Test function: %s : %s',
                            function.raw_function_name,
                            function.function_source_file)
                self.test_file_paths.add(function.function_source_file)
        return None