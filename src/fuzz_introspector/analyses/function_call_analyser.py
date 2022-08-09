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
import os

from typing import (
    List,
    Set,
    Tuple
)

from fuzz_introspector import analysis
from fuzz_introspector import html_helpers
from fuzz_introspector.datatypes import project_profile, fuzzer_profile

logger = logging.getLogger(name=__name__)


class Analysis(analysis.AnalysisInterface):
    def __init__(self) -> None:
        pass

    @staticmethod
    def get_name():
        return "FunctionCallAnalyser"

    def all_files_targeted(
        self,
        proj_profile: project_profile.MergedProjectProfile
    ) -> Set[str]:
        s1 = set()
        for prof in proj_profile.profiles:
            for func in prof.all_class_functions:
                s1.add(prof.all_class_functions[func].function_source_file)
        return s1

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

        # TODO: Add data retrieval logic

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

        # TODO: Add in table show a source files list and functions

        html_string += "</div>"  # .collapsible
        html_string += "</div>"  # report-box
        return html_string
