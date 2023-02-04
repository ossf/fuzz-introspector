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
"""Analysis for reasoning about file paths in the project"""

import logging
import os

from typing import (List, Set)

from fuzz_introspector import analysis
from fuzz_introspector import html_helpers
from fuzz_introspector.datatypes import project_profile, fuzzer_profile

logger = logging.getLogger(name=__name__)


class FilePathAnalysis(analysis.AnalysisInterface):
    name: str = "FilePathAnalyser"

    def __init__(self) -> None:
        self.json_string_result = "[]"

    @classmethod
    def get_name(cls):
        return cls.name

    def get_json_string_result(self):
        return self.json_string_result

    def set_json_string_result(self, json_string):
        self.json_string_result = json_string

    def all_files_targeted(
            self,
            proj_profile: project_profile.MergedProjectProfile) -> Set[str]:
        s1 = set()
        for prof in proj_profile.profiles:
            for func in prof.all_class_functions:
                s1.add(prof.all_class_functions[func].function_source_file)
        return s1

    def analysis_func(self,
                      table_of_contents: html_helpers.HtmlTableOfContents,
                      tables: List[str],
                      proj_profile: project_profile.MergedProjectProfile,
                      profiles: List[fuzzer_profile.FuzzerProfile],
                      basefolder: str, coverage_url: str,
                      conclusions: List[html_helpers.HTMLConclusion]) -> str:
        logger.info(f" - Running analysis {self.get_name()}")

        all_proj_files = self.all_files_targeted(proj_profile)
        all_proj_dirs = set()
        for fnm in all_proj_files:
            all_proj_dirs.add(fnm.replace(os.path.basename(fnm), ""))

        html_string = ""
        html_string += "<div class=\"report-box\">"

        # Table with all files
        html_string += html_helpers.html_add_header_with_link(
            "Files and Directories in report", html_helpers.HTML_HEADING.H1,
            table_of_contents)
        html_string += "<div class=\"collapsible\">"
        html_string += (
            "<p>This section shows which files and directories are considered "
            "in this report. The main reason for showing this is fuzz introspector "
            "may include more code in the reasoning than is desired. This section "
            "helps identify if too many files/directories are included, e.g. "
            "third party code, which may be irrelevant for the threat model. "
            "In the event too much is included, fuzz introspector supports a "
            "configuration file that can exclude data from the report. See "
            "the following link for more information on how to create a config file: "
            "<a href=\"https://github.com/ossf/fuzz-introspector/blob/main/doc/"
            "Config.md#code-exclusion-from-the-report\">link</a></p>")

        html_string += html_helpers.html_add_header_with_link(
            "Files in report", html_helpers.HTML_HEADING.H2, table_of_contents)
        tables.append(f"myTable{len(tables)}")
        html_string += html_helpers.html_create_table_head(
            tables[-1], [("Source file", ""), ("Reached by", ""),
                         ("Covered by", "")])
        for fnm in all_proj_files:
            profiles_that_hit = []
            for profile in profiles:
                if profile.reaches_file(fnm, proj_profile.basefolder):
                    profiles_that_hit.append(profile.identifier)

            profiles_that_cover = []
            for profile in profiles:
                is_file_covered = profile.is_file_covered(
                    fnm, proj_profile.basefolder)
                if is_file_covered:
                    profiles_that_cover.append(profile.identifier)

            html_string += html_helpers.html_table_add_row([
                f"{fnm}", f"{str(profiles_that_hit)}",
                f"{str(profiles_that_cover)}"
            ])
        html_string += "</table>"

        # Table with all directories
        html_string += html_helpers.html_add_header_with_link(
            "Directories in report", html_helpers.HTML_HEADING.H2,
            table_of_contents)
        tables.append(f"myTable{len(tables)}")
        html_string += html_helpers.html_create_table_head(
            tables[-1], [
                ("Directory", ""),
            ])
        for dr in all_proj_dirs:
            html_string += html_helpers.html_table_add_row([f"{dr}"])
        html_string += "</table>"

        html_string += "</div>"  # .collapsible
        html_string += "</div>"  # report-box

        return html_string
