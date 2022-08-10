# Copyright 2022 Fuzz Introspector Authors
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
"""Analysis for function call coverage in the project"""

import logging

from typing import List

from fuzz_introspector import analysis
from fuzz_introspector import html_helpers
from fuzz_introspector import utils
from fuzz_introspector.datatypes import (
    project_profile,
    fuzzer_profile,
    function_profile
)

logger = logging.getLogger(name=__name__)


class Analysis(analysis.AnalysisInterface):
    def __init__(self) -> None:
        pass

    @staticmethod
    def get_name():
        return "FunctionCallAnalyser"

    def third_party_func_profile(
        self,
        profile: project_profile.MergedProjectProfile
    ) -> List[function_profile.FunctionProfile]:
        target_list = [
            fd for fd in profile.all_functions.values() if fd.function_source_file
        ]
        return target_list

    def analysis_func(
        self,
        toc_list: List[Tuple[str, str, int]],
        tables: List[str],
        proj_profile: project_profile.MergedProjectProfile,
        profiles: List[fuzzer_profile.FuzzerProfile],
        basefolder: str,
        coverage_url: str,
        conclusions: List[html_helpers.HTMLConclusion]
    ) -> str:
        logger.info(f" - Running analysis {Analysis.get_name()}")

        # Getting data
        func_profile_list = self.third_party_func_profile(proj_profile)

        html_string = ""
        html_string += "<div class=\"report-box\">"

        html_string += html_helpers.html_add_header_with_link(
            "Function call coverage",
            1,
            toc_list
        )

        # Table with all function calls for each files
        html_string += "<div class=\"collapsible\">"
        html_string += (
            "<p>Lorem ipsum dolor sit amet</p>"
        )

        html_string += html_helpers.html_add_header_with_link(
            "Function in each files in report",
            2,
            toc_list
        )

        # Third party function calls table
        tables.append(f"myTable{len(tables)}")
        html_string += html_helpers.html_create_table_head(
            tables[-1],
            [
                ("Function name", ""),
                ("Reached by Fuzzers",
                 "The specific fuzzers that reach this function. "
                 "Based on static analysis."),
                ("Fuzzers runtime hit",
                 "Indicates whether the function is hit at runtime by the given corpus. "
                 "Based on dynamic analysis."),
                ("Reached by functions",
                 "The number of functions that reaches this function. "
                 "Based on static analysis.")
            ]
        )

        for fd in func_profile_list:
            func_name = utils.demangle_cpp_func(fd.function_name)
            hit = proj_profile.runtime_coverage.is_func_hit(fd.function_name)
            reached = len(fd.incoming_references)

            html_string += html_helpers.html_table_add_row([
                f"{func_name}",
                f"{str(fd.hitcount)}",
                f"{str(hit)}",
                f"{str(reached)}"
            ])
        html_string += "</table>"

        html_string += "</div>"  # .collapsible
        html_string += "</div>"  # report-box
        return html_string
