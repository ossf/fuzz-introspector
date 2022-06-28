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
    def __init__(self) -> None:
        self.name = "RuntimeCoverageAnalysis"

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

        functions_of_interest = self.get_low_cov_high_line_funcs(
            profiles,
            project_profile,
            min_total_lines=30,
            max_hit_proportion=55
        )

        html_string = ""
        html_string += "<div class=\"report-box\">"
        html_string += fuzz_html_helpers.html_add_header_with_link(
            "Runtime coverage analysis",
            1,
            toc_list
        )
        html_string += "<div class=\"collapsible\">"
        html_string += "<p>This section shows analysis of runtime coverage data.</p> "
        html_string += (
            f"<p>For futher technical details on how this section is generated, please "
            f"see the "
            f"<a href=\"{fuzz_constants.GIT_BRANCH_URL}/doc/Glossary.md#runtime"
            f"-coverage-analysis\">Glossary</a>.</p>"
        )
        html_string += fuzz_html_helpers.html_add_header_with_link(
            "Complex functions with low coverage", 3, toc_list)
        tables.append(f"myTable{len(tables)}")
        html_string += fuzz_html_helpers.html_create_table_head(
            tables[-1],
            [
                ("Func name", ""),
                ("Function total lines", ""),
                ("Lines covered at runtime", ""),
                ("percentage covered", ""),
                ("Reached by fuzzers", "")
            ]
        )

        for funcname in functions_of_interest:
            logger.debug(f"Iterating the function {funcname}")
            func_lines, hit_lines = project_profile.runtime_coverage.get_hit_summary(funcname)

            if func_lines is None or hit_lines is None:
                continue

            if funcname in project_profile.all_functions:
                reached_by = str(project_profile.all_functions[funcname].reached_by_fuzzers)
            else:
                reached_by = ""
            html_string += fuzz_html_helpers.html_table_add_row([
                fuzz_utils.demangle_cpp_func(funcname),
                func_lines,
                hit_lines,
                "%.5s%%" % (str((hit_lines / func_lines) * 100.0)),
                reached_by
            ])
        html_string += "</table>"
        html_string += "</div>"  # .collapsible
        html_string += "</div>"  # report-box

        logger.info(f" - Completed analysis {self.name}")
        return html_string

    def get_low_cov_high_line_funcs(
        self,
        profiles: List[fuzz_data_loader.FuzzerProfile],
        merged_profile: fuzz_data_loader.MergedProjectProfile,
        min_total_lines: int,
        max_hit_proportion: int
    ) -> List[str]:
        """
        Identifies the functions that have high line count in source code
        but only a fraction of the lines are hit at runtime.
        This is useful to highlight functions that need inspection and is
        in contrast to statically-extracted data which gives a hit/not-hit
        verdict on a given function entirely.
        """
        logger.info("Extracting low cov high line funcs")
        functions_of_interest: List[str] = []
        for funcname in merged_profile.runtime_coverage.get_all_hit_functions():
            logger.debug(f"Going through {funcname}")

            total_lines, hit_lines = merged_profile.runtime_coverage.get_hit_summary(funcname)
            logger.debug(f"Total lines: {total_lines} -- hit_lines: {hit_lines}")
            if total_lines is None or hit_lines is None or total_lines == 0:
                continue

            hit_proportion = (hit_lines / total_lines) * 100.0
            logger.debug(f"hit proportion {hit_proportion}")
            if (
                total_lines > min_total_lines
                and hit_proportion < max_hit_proportion
            ):
                functions_of_interest.append(funcname)
        return functions_of_interest
