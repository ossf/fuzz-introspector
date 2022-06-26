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
            "Files and Directories considered in report",
            1,
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
        html_string += "<br>Directories"
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

        html_string += "</div>"
        return html_string
