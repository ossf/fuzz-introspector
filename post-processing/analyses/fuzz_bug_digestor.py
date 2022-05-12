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
"""Analysis for creating input consumed by a fuzzer, e.g. a dictionary"""

import logging

from typing import (
    List,
    Tuple,
)

import fuzz_analysis
import fuzz_data_loader
import fuzz_html_helpers

logger = logging.getLogger(name=__name__)


class FuzzBugDigestorAnalysis(fuzz_analysis.AnalysisInterface):
    def __init__(self):
        self.name = "BugDigestorAnalysis"
        self.display_html = False

    def analysis_func(
        self,
        toc_list: List[Tuple[str, str, int]],
        tables: List[str],
        project_profile: fuzz_data_loader.MergedProjectProfile,
        profiles: List[fuzz_data_loader.FuzzerProfile],
        basefolder: str,
        coverage_url: str,
        conclusions
    ) -> str:
        logger.info(f" - Running analysis {self.name}")
        input_bugs = fuzz_data_loader.try_load_input_bugs()
        if len(input_bugs) == 0:
            return ""

        html_string = ""
        html_string += "<div class=\"report-box\">"
        html_string += fuzz_html_helpers.html_add_header_with_link(
            "Bug detector analysis",
            1,
            toc_list
        )

        html_string += (
            "<p>This section provices analysis that matches bugs "
            "found by fuzzers with data about the rest of the analysis. "
            "This section is still in development and should be considered "
            "beta at most.</p>"
        )

        # Create table header
        tables.append(f"myTable{len(tables)}")
        html_string += fuzz_html_helpers.html_create_table_head(
            tables[-1],
            [
                ("Bug type", "The type of bug."),
                ("Function", "The function in which the bug occurs")
            ]
        )
        for bug in input_bugs:
            logger.info("Adding row in input bugs table")
            html_string += fuzz_html_helpers.html_table_add_row(
                [
                    bug.bug_type,
                    bug.function_name
                ]
            )
        html_string += "</table>"
        html_string += "</div>"
        return html_string
