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
"""Analysis for creating optimal coverage targets"""

import logging

from typing import (
    List,
    Tuple,
)

import fuzz_analysis
import fuzz_constants
import fuzz_data_loader
import fuzz_html_helpers
import fuzz_utils

logger = logging.getLogger(name=__name__)


class FuzzRuntimeCoverageAnalysis(fuzz_analysis.AnalysisInterface):
    def __init__(self):
        self.name = "RuntimeCoverageAnalysis"

    def analysis_func(self,
                      toc_list: List[Tuple[str, str, int]],
                      tables: List[str],
                      project_profile: fuzz_data_loader.MergedProjectProfile,
                      profiles: List[fuzz_data_loader.FuzzerProfile],
                      basefolder: str,
                      coverage_url: str,
                      conclusions) -> str:
        logger.info(f" - Running analysis {self.name}")

        functions_of_interest = self.analysis_coverage_runtime_analysis(
            profiles,
            project_profile
        )

        html_string = ""
        html_string += "<div class=\"report-box\">"
        html_string += fuzz_html_helpers.html_add_header_with_link(
            "Runtime coverage analysis",
            1,
            toc_list
        )
        html_string += "<p>This section gives analysis based on data about the runtime " \
                       "coverage information</p>"
        html_string += f"<p>For futher technical details on how this section is made, please " \
                       f"see the " \
                       f"<a href=\"{fuzz_constants.GIT_BRANCH_URL}/doc/Glossary.md#runtime" \
                       f"-coverage-analysis\">Glossary</a>.</p>"
        html_string += fuzz_html_helpers.html_add_header_with_link(
            "Complex functions with low coverage", 3, toc_list)
        tables.append(f"myTable{len(tables)}")
        html_string += fuzz_html_helpers.html_create_table_head(
            tables[-1],
            [
                ("Func name", ""),
                ("Function total lines", ""),
                ("Lines covered at runtime", ""),
                ("percentage covered", "")
            ])

        for funcname in functions_of_interest:
            logger.debug(f"Iterating the function {funcname}")
            total_func_lines, hit_lines = project_profile.runtime_coverage.get_hit_summary(funcname)
            html_string += fuzz_html_helpers.html_table_add_row([
                fuzz_utils.demangle_cpp_func(funcname),
                total_func_lines,
                hit_lines,
                "%.5s%%" % (str((hit_lines / total_func_lines) * 100.0))
            ])
        html_string += "</table>"
        html_string += "</div>"  # report-box

        logger.info(f" - Completed analysis {self.name}")
        return html_string

    def analysis_coverage_runtime_analysis(
            self,
            profiles: List[fuzz_data_loader.FuzzerProfile],
            merged_profile: fuzz_data_loader.MergedProjectProfile):
        """
        Identifies the functions that are hit in terms of coverage, but
        only has a low percentage overage in terms of lines covered in the
        target program.
        This is useful to highlight functions that need inspection and is
        in contrast to statically-extracted data which gives a hit/not-hit
        verdict on a given function entirely.
        """
        logger.info("In coverage optimal analysis")

        # Find all functions that satisfy:
        # - source lines above 50
        # - less than 15% coverage
        functions_of_interest = []
        for funcname in merged_profile.runtime_coverage.get_all_hit_functions():
            logger.debug(f"Going through {funcname}")

            total_lines, hit_lines = merged_profile.runtime_coverage.get_hit_summary(funcname)
            logger.debug(f"Total lines: {total_lines} -- hit_lines: {hit_lines}")
            if total_lines == 0:
                continue

            hit_proportion = (hit_lines / total_lines) * 100.0
            logger.debug(f"hit proportion {hit_proportion}")
            if total_lines > 30 and hit_proportion < 55:
                functions_of_interest.append(funcname)
        return functions_of_interest
