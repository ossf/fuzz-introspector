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
"""Analysis for identifying optimal targets"""

import copy
import os
import json
import logging

from typing import (
    List,
    Tuple,
    Set
)

import fuzz_analysis
import fuzz_data_loader
import fuzz_html
import fuzz_html_helpers
import fuzz_utils

logger = logging.getLogger(name=__name__)


class FuzzOptimalTargetAnalysis(fuzz_analysis.AnalysisInterface):
    def __init__(self):
        self.name = "OptimalTargets"

    def analysis_func(self,
                      toc_list: List[Tuple[str, str, int]],
                      tables: List[str],
                      project_profile: fuzz_data_loader.MergedProjectProfile,
                      profiles: List[fuzz_data_loader.FuzzerProfile],
                      basefolder: str,
                      coverage_url: str,
                      conclusions,
                      should_synthetise: bool = False) -> str:
        """
        Performs an analysis based on optimal target selection.
        Finds a set of optimal functions based on complexity reach and:
          - Displays the functions in a table.
          - Calculates how the new all-function table will be in case the optimal
            targets are implemented.
          - Performs a simple synthesis on how to create fuzzers that target the
            optimal functions.
        The "optimal target function" is focused on code that is currently *not hit* by
        any fuzzers. This means it can be used to expand the current fuzzing harness
        rather than substitute it.
        """
        logger.info(f" - Running analysis {self.name}")

        html_string = ""
        html_string += fuzz_html_helpers.html_add_header_with_link(
            "Optimal target analysis", 2, toc_list)

        new_profile, optimal_target_functions = self.analysis_synthesize_simple_targets(
            project_profile
        )

        # Table with details about optimal target functions
        html_string += fuzz_html_helpers.html_add_header_with_link(
            "Remaining optimal interesting functions", 3, toc_list)
        html_string += "<p> The following table shows a list of functions that "   \
                       "are optimal targets. Optimal targets are identified by "   \
                       "finding the functions that in combination reaches a high " \
                       "amount of code coverage. </p>"
        table_id = "remaining_optimal_interesting_functions"
        tables.append(table_id)
        html_string += fuzz_html_helpers.html_create_table_head(
            table_id,
            [
                ("Func name", ""),
                ("Functions filename", ""),
                ("Arg count", ""),
                ("Args", ""),
                ("Function depth", ""),
                ("hitcount", ""),
                ("instr count", ""),
                ("bb count", ""),
                ("cyclomatic complexity", ""),
                ("Reachable functions", ""),
                ("Incoming references", ""),
                ("total cyclomatic complexity", ""),
                ("Unreached complexity", "")
            ]
        )
        for fd in optimal_target_functions:
            html_func_row = (
                f"<a href=\"#\"><code class='language-clike'>"
                f"{fuzz_utils.demangle_cpp_func(fd.function_name)}"
                f"</code></a>"
            )
            html_string += fuzz_html_helpers.html_table_add_row(
                [
                    html_func_row,
                    fd.function_source_file,
                    fd.arg_count,
                    fd.arg_types,
                    fd.function_depth,
                    fd.hitcount,
                    fd.i_count,
                    fd.bb_count,
                    fd.cyclomatic_complexity,
                    len(fd.functions_reached),
                    len(fd.incoming_references),
                    fd.total_cyclomatic_complexity,
                    fd.new_unreached_complexity
                ]
            )
        html_string += ("</table>\n")

        html_string += "<p>Implementing fuzzers that target the above functions " \
                       "will improve reachability such that it becomes:</p>"
        tables.append(f"myTable{len(tables)}")
        html_string += fuzz_html.create_top_summary_info(tables, new_profile, conclusions, False)

        # Table with details about all functions in the project in case the
        # suggested fuzzers are implemented.
        html_string += fuzz_html_helpers.html_add_header_with_link(
            "All functions overview", 4, toc_list)
        html_string += "<p> The status of all functions in the project will be as follows if you " \
                       "implement fuzzers for these functions</p>"
        table_id = "all_functions_overview_table"
        tables.append(table_id)
        all_function_table, all_functions_json = fuzz_html.create_all_function_table(
            tables, new_profile, coverage_url, basefolder, table_id)
        html_string += all_function_table
        html_string += "</div>"  # close report-box

        # Remove existing all funcs .js file
        report_name = "analysis_1.js"
        if os.path.isfile(report_name):
            os.remove(report_name)

        # Write all functions to the .js file
        with open(report_name, "a+") as all_funcs_json_file:
            all_funcs_json_file.write("var analysis_1_data = ")
            all_funcs_json_file.write(json.dumps(all_functions_json))

        logger.info(f" - Completed analysis {self.name}")
        return html_string

    def analysis_get_optimal_targets(
        self,
        merged_profile: fuzz_data_loader.MergedProjectProfile
    ) -> Tuple[List[fuzz_data_loader.FunctionProfile], Set[str]]:
        """
        Finds the top reachable functions with minimum overlap.
        Each of these functions is not be reachable by another function
        in the returned set, but, they may reach some of the same functions.
        """
        logger.info("    - in analysis_get_optimal_targets")
        optimal_set: Set[str] = set()
        target_fds: List[fuzz_data_loader.FunctionProfile] = list()

        for fd in reversed(sorted(list(merged_profile.all_functions.values()),
                                  key=lambda x: len(x.functions_reached))):
            total_vals = 0
            for t in optimal_set:
                if t in fd.functions_reached:
                    total_vals += 1

            if fd.hitcount != 0:
                continue

            if len(fd.functions_reached) < 1:
                continue

            if fd.arg_count == 0:
                continue

            # We do not care about "main2" functions
            if "main2" in fd.function_name:
                continue

            if fd.total_cyclomatic_complexity < 20:
                continue

            # Ensure that the overlap with existing functions in our optimal set is not excessive
            # set is not excessive. There is likely some overlap because of use of
            # utility functions and similar.
            # proportion = (total_vals*1.0)/(len(fd['functionsReached'])*1.0)

            # if proportion == 1.0:
            #    continue

            # condition1 = proportion < 0.5
            condition1 = True

            # We also want to include all targets that have a fairly high complexity.
            condition2 = fd.bb_count > 1

            if not (condition1 or condition2):
                continue

            for func_name in fd.functions_reached:
                optimal_set.add(func_name)

            target_fds.append(fd)
        logger.info(". Done")
        return target_fds, optimal_set

    def analysis_synthesize_simple_targets(
            self,
            merged_profile: fuzz_data_loader.MergedProjectProfile) -> (
                Tuple[
                    fuzz_data_loader.MergedProjectProfile,
                    List[fuzz_data_loader.FunctionProfile]
                ]):
        '''
        Function for synthesizing fuzz targets. The way this one works is by finding
        optimal targets that don't overlap too much with each other. The fuzz targets
        are created to target functions in specific files, so all functions targeted
        in each fuzzer will be from the same source file.
        In a sense, this is more of a PoC wy to do some analysis on the data we have.
        It is likely that we could do something much better.
        '''
        logger.info("  - in analysis_synthesize_simple_targets")
        new_merged_profile = copy.deepcopy(merged_profile)
        target_fds, optimal_set = self.analysis_get_optimal_targets(merged_profile)
        fuzzer_code = "#include \"ada_fuzz_header.h\"\n"
        fuzzer_code += "\n"
        fuzzer_code += "int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n"
        fuzzer_code += "  af_safe_gb_init(data, size);\n\n"

        optimal_functions_targeted: List[fuzz_data_loader.FunctionProfile] = []

        func_count = len(merged_profile.all_functions)
        if func_count > 20000:
            max_count = 1
        elif func_count > 10000 and func_count < 20000:
            max_count = 5
        elif func_count > 2000 and func_count < 10000:
            max_count = 7
        else:
            max_count = 10
        while len(optimal_functions_targeted) < max_count:
            logger.info("  - sorting by unreached complexity. ")
            sorted_by_undiscovered_complexity = list(
                reversed(
                    sorted(
                        target_fds,
                        key=lambda x: int(x.new_unreached_complexity)
                    )
                )
            )
            logger.info(". Done")

            try:
                tfd = sorted_by_undiscovered_complexity[0]
            except Exception:
                break
            if tfd is None:
                break

            if tfd.new_unreached_complexity <= 35:
                break

            optimal_functions_targeted.append(tfd)

            logger.info("  - calling add_func_t_reached_and_clone. ")
            new_merged_profile = fuzz_data_loader.add_func_to_reached_and_clone(
                new_merged_profile,
                tfd
            )

            # Ensure hitcount is set
            tmp_ff = new_merged_profile.all_functions[tfd.function_name]
            if tmp_ff.hitcount == 0:
                logger.info("Error. Hitcount did not get set for some reason. Exiting")
                exit(0)
            logger.info(". Done")

            # We need to update the optimal targets here.
            # We only need to do this operation if we are actually going to continue analysis

            if len(optimal_functions_targeted) < max_count:
                target_fds, optimal_set = self.analysis_get_optimal_targets(new_merged_profile)

        logger.info("Found the following optimal functions: { %s }" % (
            str([f.function_name for f in optimal_functions_targeted])))

        return new_merged_profile, optimal_functions_targeted
