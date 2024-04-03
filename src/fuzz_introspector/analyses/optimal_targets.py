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
import json
import logging

from typing import (
    List,
    Tuple,
)

from fuzz_introspector import analysis
from fuzz_introspector import constants
from fuzz_introspector import html_report
from fuzz_introspector import json_report
from fuzz_introspector import html_helpers
from fuzz_introspector import utils
from fuzz_introspector.datatypes import (project_profile, fuzzer_profile,
                                         function_profile)
from fuzz_introspector.exceptions import DataLoaderError

logger = logging.getLogger(name=__name__)


def add_func_to_reached_and_clone(
    merged_profile_old: project_profile.MergedProjectProfile,
    func_to_add: function_profile.FunctionProfile
) -> project_profile.MergedProjectProfile:
    """
    Add new functions as "reached" in a merged profile, and returns
    a new copy of the merged profile with reachability information as if the
    functions in func_to_add are added to the merged profile.
    The use of this is to calculate what the state will be of a merged profile
    by targetting a new set of functions.
    We can use this function in a computation of "optimum fuzzer target analysis", which
    computes what the combination of ideal function targets.
    """
    logger.info("Creating a deepcopy")
    merged_profile = copy.deepcopy(merged_profile_old)

    # Update hitcount of the function in the new merged profile
    logger.info("Updating hitcount")
    f = merged_profile.all_functions[func_to_add.function_name]
    if f.cyclomatic_complexity == func_to_add.cyclomatic_complexity:
        f.hitcount = 1

    # Update hitcount of all functions reached by the function
    for func_name in func_to_add.functions_reached:
        if func_name not in merged_profile.all_functions:
            if merged_profile_old.profiles[0].target_lang == "jvm":
                logger.debug(f"{func_name} not provided within classpath")
            else:
                logger.debug(f"Mismatched function name: {func_name}")
            continue
        f = merged_profile.all_functions[func_name]
        f.hitcount += 1

        f.reached_by_fuzzers.append(
            utils.demangle_cpp_func(func_to_add.function_name))

    # Recompute all analysis that is based on hitcounts in all functions as hitcount has
    # changed for elements in the dictionary.
    logger.info("Updating hitcount-related data")
    for f_profile in merged_profile.all_functions.values():
        cc = 0
        uncovered_cc = 0
        for reached_func_name in f_profile.functions_reached:
            if reached_func_name not in merged_profile.all_functions:
                if merged_profile_old.profiles[0].target_lang == "jvm":
                    logger.debug(
                        f"{reached_func_name} not provided within classpath")
                else:
                    logger.debug(
                        f"Mismatched function name: {reached_func_name}")
                continue
            f_reached = merged_profile.all_functions[reached_func_name]
            cc += f_reached.cyclomatic_complexity
            if f_reached.hitcount == 0:
                uncovered_cc += f_reached.cyclomatic_complexity

        # set complexity fields in the function
        f_profile.new_unreached_complexity = uncovered_cc
        if f_profile.hitcount == 0:
            f_profile.new_unreached_complexity += f_profile.cyclomatic_complexity
        f_profile.total_cyclomatic_complexity = cc + f_profile.cyclomatic_complexity

    if merged_profile.all_functions[func_to_add.function_name].hitcount == 0:
        logger.info("Error. Hitcount did not get set for some reason. Exiting")
        raise DataLoaderError("Hitcount did not get set for some reason")

    return merged_profile


class OptimalTargets(analysis.AnalysisInterface):
    name: str = "OptimalTargets"

    def __init__(self) -> None:
        self.json_string_result = "[]"
        self.dump_files = True

    @classmethod
    def get_name(cls):
        return cls.name

    def get_json_string_result(self):
        return self.json_string_result

    def set_json_string_result(self, json_string):
        self.json_string_result = json_string

    def analysis_func(self,
                      table_of_contents: html_helpers.HtmlTableOfContents,
                      tables: List[str],
                      proj_profile: project_profile.MergedProjectProfile,
                      profiles: List[fuzzer_profile.FuzzerProfile],
                      basefolder: str,
                      coverage_url: str,
                      conclusions: List[html_helpers.HTMLConclusion],
                      should_synthetise: bool = False) -> str:
        """
        Performs an analysis based on optimal target selection.
        Finds a set of optimal functions based on complexity reach and:

        1) Displays the functions in a table.
        2) Calculates how the new all-function table will be in case the optimal
           targets are implemented.
        3) Performs a simple synthesis on how to create fuzzers that target the
           optimal functions.

        The "optimal target function" is focused on code that is currently *not hit* by
        any fuzzers. This means it can be used to expand the current fuzzing harness
        rather than substitute it.
        """

        logger.info(f" - Running analysis {self.get_name()}")

        html_string = ""
        html_string += html_helpers.html_add_header_with_link(
            "Optimal target analysis", html_helpers.HTML_HEADING.H2,
            table_of_contents)

        # Create optimal target section
        new_profile, optimal_target_functions = self.iteratively_get_optimal_targets(
            proj_profile)
        html_string += self.get_optimal_target_section(
            optimal_target_functions, table_of_contents, tables, coverage_url,
            profiles[0].target_lang)

        # Create section for how the state of the project will be if
        # the optimal target functions are hit.
        html_string += self.get_consequential_section(new_profile, conclusions,
                                                      tables,
                                                      table_of_contents,
                                                      coverage_url, basefolder)

        logger.info(f" - Completed analysis {self.get_name()}")
        html_string += "</div>"  # .collapsible

        return html_string

    def qualifies_as_optimal_target(
            self, fd: function_profile.FunctionProfile) -> bool:
        """
        Hard conditions for whether a target qualifies as a potential
        optimal target. These are minimum conditions, i.e. the analysis
        will still pick a subset of all functions that satisfy the
        conditions.
        """
        if fd.hitcount != 0:
            return False

        if len(fd.functions_reached) < 1:
            return False

        if fd.arg_count == 0:
            return False

        # We do not care about "main2" functions
        if "main2" in fd.function_name:
            return False

        if fd.total_cyclomatic_complexity < 20:
            return False

        if fd.bb_count <= 1:
            return False

        if fd.new_unreached_complexity < 35:
            return False

        return True

    def analysis_get_optimal_targets(
        self, merged_profile: project_profile.MergedProjectProfile
    ) -> List[function_profile.FunctionProfile]:
        """
        Finds the top reachable functions with minimum overlap.
        Each of these functions is not be reachable by another function
        in the returned set, but, they may reach some of the same functions.
        """
        logger.info("    - in analysis_get_optimal_targets")

        target_fds: List[function_profile.FunctionProfile] = list()
        for fd in merged_profile.all_functions.values():
            if not self.qualifies_as_optimal_target(fd):
                continue
            target_fds.append(fd)

        return target_fds

    def iteratively_get_optimal_targets(
        self, merged_profile: project_profile.MergedProjectProfile
    ) -> Tuple[project_profile.MergedProjectProfile,
               List[function_profile.FunctionProfile]]:
        '''
        Function for synthesizing fuzz targets. The way this one works is by finding
        optimal targets that don't overlap too much with each other. The fuzz targets
        are created to target functions in specific files, so all functions targeted
        in each fuzzer will be from the same source file.
        In a sense, this is more of a PoC wy to do some analysis on the data we have.
        It is likely that we could do something much better.
        '''
        logger.info("  - in iteratively_get_optimal_targets")
        new_merged_profile = copy.deepcopy(merged_profile)
        optimal_functions_targeted: List[function_profile.FunctionProfile] = []

        # Extract all candidates
        target_fds = self.analysis_get_optimal_targets(merged_profile)

        # Determine number of fuzzers to create
        drivers_to_create = 10
        count_ranges = [
            (10000, 1),
            (5000, 3),
            (2000, 7),
        ]
        for top, count in count_ranges:
            if len(merged_profile.all_functions) > top:
                drivers_to_create = count
                break
        logger.info(f"Getting {drivers_to_create} optimal targets")
        while len(optimal_functions_targeted) < drivers_to_create:
            logger.info("  - sorting by unreached complexity. ")
            if len(target_fds) == 0:
                break
            optimal_target_fd = target_fds[0]
            for potential_target in target_fds:
                if int(potential_target.new_unreached_complexity) > int(
                        optimal_target_fd.new_unreached_complexity):
                    optimal_target_fd = potential_target

            # Add function to optimal targets
            optimal_functions_targeted.append(optimal_target_fd)

            new_merged_profile = add_func_to_reached_and_clone(
                new_merged_profile, optimal_target_fd)

            # Update the optimal targets. We only need to do this
            # if more drivers need to be created.
            if len(optimal_functions_targeted) < drivers_to_create:
                target_fds = self.analysis_get_optimal_targets(
                    new_merged_profile)

        logger.info("Found the following optimal functions: { %s }" %
                    (str([f.function_name
                          for f in optimal_functions_targeted])))

        return new_merged_profile, optimal_functions_targeted

    def get_optimal_target_section(
            self,
            optimal_target_functions: List[function_profile.FunctionProfile],
            table_of_contents: html_helpers.HtmlTableOfContents,
            tables: List[str],
            coverage_url: str,
            target_lang: str = 'c-cpp') -> str:
        # Table with details about optimal target functions
        html_string = html_helpers.html_add_header_with_link(
            "Remaining optimal interesting functions",
            html_helpers.HTML_HEADING.H3, table_of_contents)
        html_string += "<p> The following table shows a list of functions that "   \
                       "are optimal targets. Optimal targets are identified by "   \
                       "finding the functions that in combination, yield a high " \
                       "code coverage. </p>"
        table_id = "remaining_optimal_interesting_functions"
        tables.append(table_id)
        html_string += html_helpers.html_create_table_head(
            table_id, [("Func name", ""), ("Functions filename", ""),
                       ("Arg count", ""), ("Args", ""), ("Function depth", ""),
                       ("hitcount", ""), ("instr count", ""), ("bb count", ""),
                       ("cyclomatic complexity", ""),
                       ("Reachable functions", ""),
                       ("Incoming references", ""),
                       ("total cyclomatic complexity", ""),
                       ("Unreached complexity", "")])
        for fd in optimal_target_functions:
            func_cov_url = utils.resolve_coverage_link(coverage_url,
                                                       fd.function_source_file,
                                                       fd.function_linenumber,
                                                       fd.function_name,
                                                       target_lang)
            html_func_row = (
                f"<a href=\"{ func_cov_url }\"><code class='language-clike'>"
                f"{utils.demangle_cpp_func(fd.function_name)}"
                f"</code></a>")
            html_string += html_helpers.html_table_add_row([
                html_func_row, fd.function_source_file, fd.arg_count,
                fd.arg_types, fd.function_depth, fd.hitcount, fd.i_count,
                fd.bb_count, fd.cyclomatic_complexity,
                len(fd.functions_reached),
                len(fd.incoming_references), fd.total_cyclomatic_complexity,
                fd.new_unreached_complexity
            ])

        json_dict = list()
        for fd in optimal_target_functions:
            json_dict.append({
                'name':
                fd.function_name,
                'source_file':
                fd.function_source_file,
                'new-unreached-complexity':
                fd.new_unreached_complexity,
                'cyclomatic_complexity':
                fd.cyclomatic_complexity,
                'function_depth':
                fd.function_depth,
                'total_cyclomatic_complexity':
                fd.total_cyclomatic_complexity
            })

        self.set_json_string_result(json.dumps(json_dict))

        json_report.add_analysis_json_str_as_dict_to_report(
            self.get_name(), self.get_json_string_result())
        html_string += ("</table>\n")
        return html_string

    def create_top_summary_info(
            self, tables: List[str],
            proj_profile: project_profile.MergedProjectProfile) -> str:
        html_string = ""

        # Display reachability information
        html_string += "<div style=\"display: flex; max-width: 50%\">"

        html_string += html_helpers.create_percentage_graph(
            "Functions statically reachable by fuzzers",
            proj_profile.reached_func_count, proj_profile.total_functions)

        html_string += html_helpers.create_percentage_graph(
            "Cyclomatic complexity statically reachable by fuzzers",
            proj_profile.reached_complexity, proj_profile.total_complexity)

        html_string += "</div>"

        return html_string

    def get_consequential_section(
            self, new_profile: project_profile.MergedProjectProfile,
            conclusions: List[html_helpers.HTMLConclusion], tables: List[str],
            table_of_contents: html_helpers.HtmlTableOfContents,
            coverage_url: str, basefolder: str) -> str:
        """Create section showing state of project if optimal targets are hit"""
        html_string = (
            "<p>Implementing fuzzers that target the above functions "
            "will improve reachability such that it becomes:</p>")
        tables.append(f"myTable{len(tables)}")
        html_string += self.create_top_summary_info(tables, new_profile)

        # Table with details about all functions in the project in case the
        # suggested fuzzers are implemented.
        html_string += html_helpers.html_add_header_with_link(
            "All functions overview", html_helpers.HTML_HEADING.H4,
            table_of_contents)
        html_string += "<p> If you implement fuzzers for these functions, the status of all " \
                       "functions in the project will be:</p>"
        table_id = "all_functions_overview_table"
        tables.append(table_id)
        all_function_table, all_functions_json, _ = html_report.create_all_function_table(
            tables, new_profile, coverage_url, basefolder, table_id)
        html_string += all_function_table
        html_string += "</div>"  # close report-box

        # Write all functions to the .js file
        if self.dump_files:
            with open(constants.OPTIMAL_TARGETS_ALL_FUNCTIONS,
                      'w') as func_file:
                func_file.write("var analysis_1_data = ")
                func_file.write(json.dumps(all_functions_json))
        return html_string
