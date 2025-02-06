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
"""Analysis plugin for introspection to extract all publicly accessible
non-standard library functions."""

import os
import json
import logging

from typing import (Any, List, Dict)

from fuzz_introspector import (analysis, html_helpers)

from fuzz_introspector.datatypes import (project_profile, fuzzer_profile,
                                         function_profile)

logger = logging.getLogger(name=__name__)


class PublicCandidateAnalyser(analysis.AnalysisInterface):
    """Exract all public non-standard libary functions fron the project."""

    name: str = 'PublicCandidateAnalyser'

    def __init__(self) -> None:
        self.json_results: Dict[str, Any] = {}
        self.json_string_result = ''
        self.dump_files = True

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

    def set_json_string_result(self, string):
        """Store the result of this analyser as json string result
        for further processing in a later time.

        :param json_string: A json string variable storing the
            processing result of the analyser for future use
        :type json_string: str
        """
        self.json_string_result = string

    def analysis_func(self,
                      table_of_contents: html_helpers.HtmlTableOfContents,
                      tables: List[str],
                      proj_profile: project_profile.MergedProjectProfile,
                      profiles: List[fuzzer_profile.FuzzerProfile],
                      basefolder: str, coverage_url: str,
                      conclusions: List[html_helpers.HTMLConclusion],
                      out_dir: str) -> str:
        self.standalone_analysis(proj_profile, profiles, out_dir)
        return ''

    def standalone_analysis(self,
                            proj_profile: project_profile.MergedProjectProfile,
                            profiles: List[fuzzer_profile.FuzzerProfile],
                            out_dir: str) -> None:
        super().standalone_analysis(proj_profile, profiles, out_dir)

        logger.info(' - Running analysis %s', self.get_name())

        # Get all functions from the profiles
        all_functions = list(proj_profile.all_functions.values())
        all_functions.extend(proj_profile.all_constructors.values())

        # Filter and sort functions
        filtered_functions = self._filter_functions(all_functions)
        sorted_functions = self._sort_functions(filtered_functions,
                                                proj_profile)

        # Convert functions to dict
        result_list = [
            function.to_dict(
                proj_profile.get_func_hit_percentage(function.function_name))
            for function in sorted_functions
        ]

        if self.dump_files:
            result_json_path = os.path.join(out_dir, 'result.json')
            logger.info('Found %d function candidiates.', len(result_list))
            logger.info('Dumping result to %s', result_json_path)
            with open(result_json_path, 'w') as f:
                json.dump(result_list, f)

    def _filter_functions(
        self, functions: list[function_profile.FunctionProfile]
    ) -> list[function_profile.FunctionProfile]:
        """Filter unrelated functions in a provided function list if
        it meet any of the following conditions.
        1) Fuzzing related methods / functions
        2) Functions with name contains word "exception / error / test"
        """
        excluded_function_name = [
            'fuzzertestoneinput', 'fuzzerinitialize', 'fuzzerteardown',
            'exception', 'error', 'test', 'llvmfuzertestoneinput',
            'fuzz_target'
        ]

        return [
            function for function in functions
            if (function.is_accessible and not function.is_jvm_library
                and function.arg_count > 0 and not any(
                    function_name in function.function_name.lower()
                    for function_name in excluded_function_name))
        ]

    def _sort_functions(
        self,
        functions: list[function_profile.FunctionProfile],
        proj_profile: project_profile.MergedProjectProfile,
    ) -> list[function_profile.FunctionProfile]:
        """Sort the function list according to the following criteria in order.
        The order is acscending unless otherwise specified.
        For boolean sorting, False is always come first in acscending order.
        1) If the function is reached by any existing fuzzers.
        2) If the function belongs to a enum class (only for JVM project).
        3) The runtime code coverage of the function.
        4) The function call depth in descending order.
        5) The cyclomatic complexity of the function in descending order.
        6) The undiscovered complexity of the function.
        7) The number of arguments of this function in descending order.
        8) Number of source code lines in descending order.
        9) The number of how many fuzzers reached this target function.
        """
        return sorted(
            functions,
            key=lambda item:
            (bool(item.reached_by_fuzzers), item.is_enum,
             proj_profile.get_func_hit_percentage(item.function_name), -item.
             function_depth, -item.cyclomatic_complexity, item.
             new_unreached_complexity, -item.arg_count, -(
                 item.function_line_number_end - item.function_linenumber),
             len(item.reached_by_fuzzers)),
            reverse=False)
