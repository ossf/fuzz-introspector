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
"""Analysis plugin for introspection of the function on target line in
target source file."""

import os
import json
import logging

from typing import (Any, List, Dict)

from fuzz_introspector import (analysis, html_helpers)

from fuzz_introspector.datatypes import (project_profile, fuzzer_profile,
                                         function_profile)

logger = logging.getLogger(name=__name__)


class SourceCodeLineAnalyser(analysis.AnalysisInterface):
    """Locate for the function in given line of given source file."""

    name: str = 'SourceCodeLineAnalyser'

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

    def set_source_file_line(self, source_file: str, source_line: int):
        """Configure the source file and source line for this analyser."""
        self.source_file = source_file
        self.source_line = source_line

    def analysis_func(self,
                      table_of_contents: html_helpers.HtmlTableOfContents,
                      tables: List[str],
                      proj_profile: project_profile.MergedProjectProfile,
                      profiles: List[fuzzer_profile.FuzzerProfile],
                      basefolder: str, coverage_url: str,
                      conclusions: List[html_helpers.HTMLConclusion],
                      out_dir: str) -> str:
        logger.info(' - Running analysis %s', self.get_name())

        if not self.source_file or self.source_line <= 0:
            logger.error('No valid source code or target line are provided')
            return ''

        # Get all functions from the profiles
        all_functions = list(proj_profile.all_functions.values())
        all_functions.extend(proj_profile.all_constructors.values())

        # Generate SourceFile to Function Profile map and store in JSON Result
        func_file_map: dict[str, list[function_profile.FunctionProfile]] = {}
        for function in all_functions:
            func_list = func_file_map.get(function.function_source_file, [])
            func_list.append(function)
            func_file_map[function.function_source_file] = func_list

        if os.sep in self.source_file:
            # File path
            target_func_list = func_file_map.get(self.source_file, [])
        else:
            # File name
            target_func_list = []
            for key, value in func_file_map.items():
                if os.path.basename(key) == self.source_file:
                    target_func_list.extend(value)

        if not target_func_list:
            logger.error(
                'Failed to locate the target source file %s from the project.',
                self.source_file)

        result_list = []
        for func in target_func_list:
            start = func.function_linenumber
            end = func.function_line_number_end
            if start <= self.source_line <= end:
                logger.info('Found function %s from line %d in %s',
                            func.function_name, self.source_line,
                            self.source_file)
                result_list.append(
                    func.to_dict(
                        proj_profile.get_func_hit_percentage(
                            func.function_name)))

        if result_list:
            self.json_results['functions'] = result_list
            result_json_path = os.path.join(out_dir, 'functions.json')
            logger.info('Dumping result to %s', result_json_path)
            with open(result_json_path, 'w') as f:
                json.dump(self.json_results, f)
        else:
            logger.info('No functions found from line %d in %s',
                        self.source_line, self.source_file)

        return ''
