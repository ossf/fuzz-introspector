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
"""Analysis plugin for introspection of the functions which are far
reached and with low coverage."""
import os
import json
import logging

from typing import (Any, List, Dict)

from fuzz_introspector import (analysis, html_helpers)

from fuzz_introspector.datatypes import (project_profile, fuzzer_profile,
                                         function_profile)

logger = logging.getLogger(name=__name__)


class FarReachLowCoverageAnalyser(analysis.AnalysisInterface):
    """Locate for the functions which are far reached and with
    low coverage."""

    name: str = 'FarReachLowCoverageAnalyser'

    def __init__(self) -> None:
        self.json_results: Dict[str, Any] = {}
        self.json_string_result = ''

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

    def set_flags(self, exclude_static_functions: bool,
                  only_referenced_functions: bool, only_header_functions: bool,
                  only_interesting_functions: bool):
        """Configure the flags from the CLI."""
        self.exclude_static_functions = exclude_static_functions
        self.only_referenced_functions = only_referenced_functions
        self.only_header_functions = only_header_functions
        self.only_interesting_functions = only_interesting_functions

    def set_max_functions(self, max_functions: int):
        """Configure the max functions to return from CLI."""
        self.max_functions = max_functions

    def set_introspection_project(
            self, introspection_project: analysis.IntrospectionProject):
        """Configure the introspection project wrapper for retrieving
        debug data."""
        self.introspection_project = introspection_project

    def analysis_func(self,
                      table_of_contents: html_helpers.HtmlTableOfContents,
                      tables: List[str],
                      proj_profile: project_profile.MergedProjectProfile,
                      profiles: List[fuzzer_profile.FuzzerProfile],
                      basefolder: str, coverage_url: str,
                      conclusions: List[html_helpers.HTMLConclusion],
                      out_dir: str) -> str:
        logger.info(' - Running analysis %s', self.get_name())
        logger.info(
            ' - Settings: exclude_static_functions: %s, '
            'only_referenced_functions: %s, '
            'only_header_functions: %s, '
            'only_interesting_functions: %s, '
            'max_functions: %d', self.exclude_static_functions,
            self.only_referenced_functions, self.only_header_functions,
            self.only_interesting_functions, self.max_functions)

        result_list: List[Dict[str, Any]] = []

        # Get all functions from the profiles
        all_functions = list(proj_profile.all_functions.values())
        all_functions.extend(proj_profile.all_constructors.values())

        # Get cross reference function dict
        if self.only_referenced_functions:
            xref_dict = self._get_cross_reference_dict(all_functions)
        else:
            xref_dict = {}

        # Get interesting functions sorted by complexity and runtime coverage
        filtered_functions = self._get_functions_of_interest(
            all_functions, proj_profile)

        # Process the final result list of functions according to the
        # configured flags
        for function in filtered_functions:
            # Check for max_functions count
            if len(result_list) >= self.max_functions:
                break

            # Check for only_referenced_functions flag
            if (self.only_referenced_functions
                    and function.function_name not in xref_dict):
                continue

            # Check for only_header_functions
            # TODO No Debug information from the new frontend yet.
            # Handle this later

            # Check for exclude_static_functions flag
            # TODO No Debug information from the new frontend yet.
            # Handle this later

            # Check for interesting functions with fuzz keywords
            if (self.only_interesting_functions
                    and not self._is_interesting_function_with_fuzz_keywords(
                        function)):
                continue

            result_list.append(
                function.to_dict(
                    proj_profile.get_func_hit_percentage(
                        function.function_name)))

        self.json_results['functions'] = result_list
        result_json_path = os.path.join(out_dir, 'result.json')
        logger.info('Found %d function candidiates.', len(result_list))
        logger.info('Dumping result to %s', result_json_path)
        with open(result_json_path, 'w') as f:
            json.dump(self.json_results, f)

        return ''

    def _get_cross_reference_dict(
            self, functions: List[function_profile.FunctionProfile]
    ) -> Dict[str, int]:
        """Internal helper function to build up a function cross reference
        dict."""
        func_xrefs: Dict[str, int] = {}

        for function in functions:
            for dst, src_list in function.callsite.items():
                func_xrefs_count = func_xrefs.get(dst, 0)
                func_xrefs_count += len(src_list)
                func_xrefs[dst] = func_xrefs_count

        return func_xrefs

    def _get_functions_of_interest(
        self,
        functions: List[function_profile.FunctionProfile],
        proj_profile: project_profile.MergedProjectProfile,
    ) -> List[function_profile.FunctionProfile]:
        """Internal helper function to get a sorted functions of interest."""
        filtered_functions = []

        for function in functions:
            # Skipping non-related jvm methods and methods from enum classes
            # is_accessible is True by default, i.e. for non jvm projects
            if (not function.is_accessible or function.is_jvm_library
                    or function.is_enum):
                continue

            coverage = proj_profile.get_func_hit_percentage(
                function.function_name)

            if coverage < 20.0:
                filtered_functions.append(function)

        # Sort the filtered functions
        filtered_functions.sort(key=lambda x: (
            -x.cyclomatic_complexity,
            proj_profile.get_func_hit_percentage(x.function_name)))

        return filtered_functions

    def _is_interesting_function_with_fuzz_keywords(
            self, function: function_profile.FunctionProfile) -> bool:
        """Internal helper to determine if it is interesting for fuzzing."""
        interesting_fuzz_keywords = [
            'deserialize',
            'parse',
            'parse_xml',
            'read_file',
            'read_json',
            'read_xml',
            'request',
            'parse_header',
            'parse_request',
            'compress',
            'file_read',
            'read_message',
            'load_image',
        ]

        if any(fuzz_keyword in function.function_name.lower() or
               fuzz_keyword.replace('_', '') in function.function_name.lower()
               for fuzz_keyword in interesting_fuzz_keywords):
            return True

        return False
