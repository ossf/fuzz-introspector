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

from fuzz_introspector import analysis
from fuzz_introspector import data_loader
from fuzz_introspector import html_helpers
from fuzz_introspector.datatypes import project_profile, fuzzer_profile

logger = logging.getLogger(name=__name__)


class BugDigestor(analysis.AnalysisInterface):
    """Analysis for creating input consumed by a fuzzer, e.g. a dictionary
    and fuzzer focus functions in libFuzzer. The analysis outputs this either
    in .json format or as HTML string that can be embedded in the HTML report.
    """
    name: str = "BugDigestorAnalysis"

    def __init__(self) -> None:
        self.display_html = False
        self.json_string_result = "[]"

    @classmethod
    def get_name(cls):
        return cls.name

    def get_json_string_result(self):
        return self.json_string_result

    def set_json_string_result(self, json_string):
        self.json_string_result = json_string

    def analysis_func(self, toc_list: List[Tuple[str, str,
                                                 int]], tables: List[str],
                      proj_profile: project_profile.MergedProjectProfile,
                      profiles: List[fuzzer_profile.FuzzerProfile],
                      basefolder: str, coverage_url: str,
                      conclusions: List[html_helpers.HTMLConclusion]) -> str:
        """Digests and creates HTML about bugs found by the fuzzers."""
        logger.info(f" - Running analysis {self.get_name()}")
        input_bugs = data_loader.try_load_input_bugs()
        if len(input_bugs) == 0:
            return ""

        html_string = ""
        html_string += "<div class=\"report-box\">"
        html_string += html_helpers.html_add_header_with_link(
            "Bug detector analysis", html_helpers.HTML_HEADING.H1, toc_list)
        html_string += "<div class=\"collapsible\">"

        html_string += (
            "<p>This section provices analysis that matches bugs "
            "found by fuzzers with data about the rest of the analysis. "
            "This section is still in development and should be considered "
            "beta at most.</p>")

        # Create table header
        tables.append(f"myTable{len(tables)}")
        html_string += html_helpers.html_create_table_head(
            tables[-1], [("Bug type", "The type of bug."),
                         ("Function", "The function in which the bug occurs")])
        for bug in input_bugs:
            logger.info("Adding row in input bugs table")
            html_string += html_helpers.html_table_add_row(
                [bug.bug_type, bug.function_name])
        html_string += "</table>"
        html_string += "</div>"  # .collapsible
        html_string += "</div>"  # report-box

        return html_string
