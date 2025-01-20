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
"""Analysis plugin for introspection of the function on target line in target source file."""

import os
import json
import logging

from typing import (Any, List, Dict)

from fuzz_introspector import (analysis, html_helpers)

from fuzz_introspector.datatypes import (project_profile, fuzzer_profile)

logger = logging.getLogger(name=__name__)


class SourceCodeLineAnalyser(analysis.AnalysisInterface):
    name: str = 'SourceCodeLineAnalyser'

    def __init__(self):
        self.json_results: Dict[str, Any] = dict()
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

    def set_json_string_result(self, json_string):
        """Store the result of this analyser as json string result
        for further processing in a later time.

        :param json_string: A json string variable storing the
            processing result of the analyser for future use
        :type json_string: str
        """
        self.json_string_result = json_string

    def analysis_func(self,
                      table_of_contents: html_helpers.HtmlTableOfContents,
                      tables: List[str],
                      proj_profile: project_profile.MergedProjectProfile,
                      profiles: List[fuzzer_profile.FuzzerProfile],
                      basefolder: str, coverage_url: str,
                      conclusions: List[html_helpers.HTMLConclusion],
                      out_dir) -> str:
        logger.info(f' - Running analysis {self.get_name()}')

        # Get target source file and line
        target_source = self.properties.get('source_file')
        target_line = self.properties.get('line')

        if not target_source or not isinstance(target_line, int) or target_line <= 0:
            logger.error('No valid source code or target line are provided')
            return ''

        # Get all functions from the profiles
        all_functions = list(proj_profile.all_functions.values())
        all_functions.extend(proj_profile.all_constructors.values())

        # Generate a Source File to Function Profile map and store in JSON Result
        func_file_map = {}
        for function in all_functions:
            func_list = func_file_map.get(function.function_source_file_path,
                                              [])
            func_list.append(function)
            func_file_map[function.function_source_file_path] = func_list

        if os.sep in target_source:
            # File path
            target_func_list = func_file_map.get(target_source, [])
        else:
            # File name
            target_func_list = []
            for key, value in func_file_map.items():
                if os.path.basename(key) == target_source:
                    target_func_list.extend(value)

        if not target_func_list:
            logger.error('Failed to locate the target source file '
                         f'{target_source} from the project.')

        result_list = []
        for func in target_func_list:
            if func.function_linenumber <= target_line <= func.function_line_number_end:
                logger.info(f'Found function {func.function_name} from line {target_line} in {target_source}')
                result_list.append(func)

        if result_list:
            self.json_results['functions'] = result_list

        return ''
