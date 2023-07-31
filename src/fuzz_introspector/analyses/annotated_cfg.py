# Copyright 2023 Fuzz Introspector Authors
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
"""Creates an annotated CFG, focusing on only a subset of the CFG atm."""

import logging
import json

from typing import (Any, Dict, List)

from fuzz_introspector import analysis
from fuzz_introspector import utils
from fuzz_introspector import cfg_load
from fuzz_introspector import json_report
from fuzz_introspector import html_helpers
from fuzz_introspector.datatypes import project_profile, fuzzer_profile

logger = logging.getLogger(name=__name__)


class FuzzAnnotatedCFG(analysis.AnalysisInterface):
    name: str = "AnnotatedCFG"

    def __init__(self) -> None:
        logger.info("Creating annotated CFG")
        self.json_string_result = ""
        self.json_results: Dict[str, Any] = dict()
        self.dump_files = False

    @classmethod
    def get_name(cls):
        return cls.name

    def get_json_string_result(self):
        return json.dumps(self.json_results)

    def set_json_string_result(self, json_string):
        self.json_string_result = json_string

    def analysis_func(self,
                      table_of_contents: html_helpers.HtmlTableOfContents,
                      tables: List[str],
                      proj_profile: project_profile.MergedProjectProfile,
                      profiles: List[fuzzer_profile.FuzzerProfile],
                      basefolder: str, coverage_url: str,
                      conclusions: List[html_helpers.HTMLConclusion]) -> str:
        """
        Creates the HTML of the calltree. Returns the HTML as a string.
        """
        logger.info("Creating annotated CFGs")

        for profile in profiles:
            logger.info("Analysing: %s" % (profile.identifier))
            destinations = []
            src_file = None
            for callsite in cfg_load.extract_all_callsites(
                    profile.fuzzer_callsite_calltree):
                if callsite.depth < 2:
                    dst_fd = self.get_profile_sourcefile(
                        profile, callsite.dst_function_name)
                    if dst_fd is None:
                        dst_fd = self.get_profile_sourcefile(
                            profile,
                            "[%s].%s" % (callsite.dst_function_source_file,
                                         callsite.dst_function_name))
                        if dst_fd is None:
                            continue
                    if callsite.depth == 0:
                        src_file = dst_fd.function_source_file
                    else:
                        if dst_fd.function_source_file == "":
                            continue
                        destinations.append({
                            'function-name':
                            dst_fd.function_name,
                            'source-file':
                            dst_fd.function_source_file,
                            'cyclomatic-complexity':
                            dst_fd.cyclomatic_complexity,
                            'accummulated-cyclomatic-complexity':
                            dst_fd.total_cyclomatic_complexity,
                            'return-type':
                            dst_fd.return_type,
                            'arg-list':
                            dst_fd.arg_types
                        })
            self.json_results[profile.identifier] = {
                'destinations': destinations,
                'src_file': src_file
            }

        # Write the results to the json report
        json_report.add_analysis_json_str_as_dict_to_report(
            self.get_name(), self.get_json_string_result())
        return ""

    def get_profile_sourcefile(self, profile, func_name):
        dst_options = [
            func_name,
            utils.demangle_cpp_func(func_name),
        ]
        for dst in dst_options:
            for fd_k, fd in profile.all_class_functions.items():
                if (fd.function_name == dst or utils.normalise_str(
                        fd.function_name) == utils.normalise_str(dst)):
                    return fd
        return None
