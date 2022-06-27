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

from typing import (
    List,
    Set,
    Tuple
)

import fuzz_analysis
import fuzz_data_loader
import fuzz_html_helpers

logger = logging.getLogger(name=__name__)


class FuzzFilepathAnalyser(fuzz_analysis.AnalysisInterface):
    def __init__(self) -> None:
        self.name = "FilePathAnalyser"

    def all_files_targeted(
        self,
        project_profile: fuzz_data_loader.MergedProjectProfile
    ) -> Set[str]:
        s1 = set()
        for prof in project_profile.profiles:
            for func in prof.all_class_functions:
                s1.add(prof.all_class_functions[func].function_source_file)
        return s1

    def analysis_func(
        self,
        toc_list: List[Tuple[str, str, int]],
        tables: List[str],
        project_profile: fuzz_data_loader.MergedProjectProfile,
        profiles: List[fuzz_data_loader.FuzzerProfile],
        basefolder: str,
        coverage_url: str,
        conclusions: List[Tuple[int, str]]
    ) -> str:
        logger.info(f" - Running analysis {self.name}")

        all_proj_files = self.all_files_targeted(project_profile)
        all_proj_dirs = set()
        for fnm in all_proj_files:
            all_proj_dirs.add(fnm.replace(os.path.basename(fnm), ""))

        html_string = ""
        html_string += "<div class=\"report-box\">"

        # Table with all files
        html_string += fuzz_html_helpers.html_add_header_with_link(
            "Files and Directories in report",
            1,
            toc_list
        )
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
            "Config.md#code-exclusion-from-the-report\">link</a></p>"
        )

        html_string += fuzz_html_helpers.html_add_header_with_link(
            "Files in report",
            2,
            toc_list
        )
        tables.append(f"myTable{len(tables)}")
        html_string += fuzz_html_helpers.html_create_table_head(
            tables[-1],
            [
                ("Source file", ""),
            ]
        )
        for fnm in all_proj_files:
            html_string += fuzz_html_helpers.html_table_add_row([f"{fnm}"])
        html_string += "</table>"

        # Table with all directories
        html_string += fuzz_html_helpers.html_add_header_with_link(
            "Directories in report",
            2,
            toc_list
        )
        tables.append(f"myTable{len(tables)}")
        html_string += fuzz_html_helpers.html_create_table_head(
            tables[-1],
            [
                ("Directory", ""),
            ]
        )
        for dr in all_proj_dirs:
            html_string += fuzz_html_helpers.html_table_add_row([f"{dr}"])
        html_string += "</table>"

        html_string += "</div>"  # .collapsible
        html_string += "</div>"  # report-box
        return html_string
