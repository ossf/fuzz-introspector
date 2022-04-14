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

import os
import json
import logging

from typing import (
    List,
    Tuple,
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
        logger.info(" - Identifying optimal targets")

        html_string = ""
        html_string += fuzz_html_helpers.html_add_header_with_link(
            "Optimal target analysis", 2, toc_list)
        (fuzz_targets,
         new_profile,
         optimal_target_functions) = fuzz_analysis.analysis_synthesize_simple_targets(
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
            html_string += fuzz_html_helpers.html_table_add_row([
                "<a href=\"#\"><code class='language-clike'>%s</code></a>" % (
                    fuzz_utils.demangle_cpp_func(fd.function_name)),
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
                fd.new_unreached_complexity])
        html_string += ("</table>\n")

        html_string += "<p>Implementing fuzzers that target the above functions " \
                       "will improve reachability such that it becomes:</p>"
        tables.append(f"myTable{len(tables)}")
        # html_string += create_top_summary_info(tables, new_profile, conclusions, False)

        # Section with code for new fuzzing harnesses
        if should_synthetise:
            html_string += fuzz_html_helpers.html_add_header_with_link("New fuzzers", 3, toc_list)
            html_string += "<p>The below fuzzers are templates and suggestions for how " \
                           "to target the set of optimal functions above</p>"
            for filename in fuzz_targets:
                html_string += fuzz_html_helpers.html_add_header_with_link(
                    "%s" % filename.split("/")[-1],
                    4,
                    toc_list
                )
                html_string += "<b>Target file:</b>%s<br>" % (filename)
                all_functions = ", ".join(
                    [f.function_name for f in fuzz_targets[filename]['target_fds']]
                )
                html_string += "<b>Target functions:</b> %s" % (all_functions)
                html_string += "<pre><code class='language-clike'>%s</code></pre><br>" % (
                    fuzz_targets[filename]['source_code'])

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

        return html_string
