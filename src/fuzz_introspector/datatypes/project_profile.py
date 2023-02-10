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
"""Project profile"""

import os
import logging

from typing import (
    Dict,
    List,
    Tuple,
)

from fuzz_introspector import (code_coverage, exceptions, json_report, utils)
from fuzz_introspector.datatypes import function_profile, fuzzer_profile

logger = logging.getLogger(name=__name__)


class MergedProjectProfile:
    """
    Class for storing information about all fuzzers combined in a given project.
    This means, it contains data for all fuzzers in a given project, and digests
    the manner in a way that makes sense from a project-scope perspective. For
    example, it does project-wide analysis of reachable/unreachable functions by
    digesting data from all the fuzzers in the project.
    """

    def __init__(self, profiles: List[fuzzer_profile.FuzzerProfile]):
        self.name = None
        self.profiles = profiles
        self.all_functions: Dict[str,
                                 function_profile.FunctionProfile] = dict()
        self.unreached_functions = set()
        self.functions_reached = set()
        self.coverage_url = "#"

        logger.info(
            f"Creating merged profile of {len(self.profiles)} profiles")
        # Populate functions reached
        logger.info("Populating functions reached")
        for profile in profiles:
            for func_name in profile.functions_reached_by_fuzzer:
                self.functions_reached.add(func_name)

        # Set all unreached functions
        logger.info("Populating functions unreached")
        for profile in profiles:
            for func_name in profile.functions_unreached_by_fuzzer:
                if func_name not in self.functions_reached:
                    self.unreached_functions.add(func_name)

        # Add all functions from the various profiles into the merged profile. Don't
        # add duplicates
        logger.info("Creating all_functions dictionary")
        excluded_functions = {"sanitizer", "llvm", "LLVMFuzzerTestOneInput"}
        for profile in profiles:
            for fd in profile.all_class_functions.values():
                # continue if the function is to be excluded
                if len([
                        ef
                        for ef in excluded_functions if ef in fd.function_name
                ]) != 0:
                    continue

                # populate hitcount and reached_by_fuzzers and whether it has been handled already
                for profile2 in profiles:
                    if profile2.reaches_func(fd.function_name):
                        fd.hitcount += 1
                        fd.reached_by_fuzzers.append(profile2.identifier)
                    if fd.function_name not in self.all_functions:
                        self.all_functions[fd.function_name] = fd

        # Gather complexity information about each function
        logger.info(
            "Gathering complexity and incoming references of each function")
        for fp_obj in self.all_functions.values():
            total_cyclomatic_complexity = 0
            total_new_complexity = 0

            for reached_func_name in fp_obj.functions_reached:
                if reached_func_name not in self.all_functions:
                    if profile.target_lang == "jvm":
                        logger.debug(
                            f"{reached_func_name} not provided within classpath"
                        )
                    else:
                        logger.error(
                            f"Mismatched function name: {reached_func_name}")
                    continue
                reached_func_obj = self.all_functions[reached_func_name]
                reached_func_obj.incoming_references.append(
                    fp_obj.function_name)
                total_cyclomatic_complexity += reached_func_obj.cyclomatic_complexity
                if reached_func_obj.hitcount == 0:
                    total_new_complexity += reached_func_obj.cyclomatic_complexity
            if fp_obj.hitcount == 0:
                fp_obj.new_unreached_complexity = (
                    total_new_complexity + fp_obj.cyclomatic_complexity)
            else:
                fp_obj.new_unreached_complexity = total_new_complexity
            fp_obj.total_cyclomatic_complexity = (total_cyclomatic_complexity +
                                                  fp_obj.cyclomatic_complexity)

        # Accumulate run-time coverage mapping
        self.runtime_coverage = code_coverage.CoverageProfile()
        for profile in profiles:
            if profile.coverage is None:
                continue
            for func_name in profile.coverage.covmap:
                if func_name not in self.runtime_coverage.covmap:
                    self.runtime_coverage.covmap[
                        func_name] = profile.coverage.covmap[func_name]
                else:
                    # Merge by picking highest line numbers. Here we can assume they coverage
                    # maps have the same number of elements with the same line numbers but
                    # different hit counts.
                    new_line_counts = list()
                    for idx1 in range(
                            len(self.runtime_coverage.covmap[func_name])):
                        try:
                            ln1, ht1 = self.runtime_coverage.covmap[func_name][
                                idx1]
                            ln2, ht2 = profile.coverage.covmap[func_name][idx1]
                        except Exception:
                            ln1, ht1 = self.runtime_coverage.covmap[func_name][
                                idx1]
                            ln2, ht2 = self.runtime_coverage.covmap[func_name][
                                idx1]
                        # It may be that line numbers are not the same for the same function
                        # name across different fuzzers.
                        # This *could* actually happen, and will often (almost always) happen for
                        # LLVMFuzzerTestOneInput. In this case we just gracefully
                        # continue and ignore issues.
                        if ln1 != ln2:
                            logger.info(
                                f"Line numbers are different in the same function: "
                                f"{func_name}:{ln1}:{ln2}, ignoring")
                            continue
                        new_line_counts.append((ln1, max(ht1, ht2)))
                    self.runtime_coverage.covmap[func_name] = new_line_counts
            # TODO (navidem): will need to merge branch coverages (branch_cov_map) if we need to
            # identify blockers based on all fuzz targets coverage
        self._set_basefolder()
        logger.info("Completed creationg of merged profile")

    def get_all_runtime_covered_functions(self) -> List[str]:
        """Gets the name of all functions that are covered by runtime
        code coverage analysis.

        :rtype: List[str]
        :returns: List of strings corresponding to function names
        """
        all_covered_functions = []
        for funcname in self.runtime_coverage.covmap:
            all_covered_functions.append(funcname)
        return all_covered_functions

    def get_function_summaries(self) -> Tuple[int, int, int, float, float]:
        """Gets data points summarising data with respect to static reachability of
        all functions in the project.
        """
        reached_func_count = self._get_total_reached_function_count()
        unreached_func_count = self._get_total_unreached_function_count()
        total_functions = reached_func_count + unreached_func_count
        reached_percentage = (float(reached_func_count) /
                              float(total_functions)) * 100
        unreached_percentage = (float(unreached_func_count) /
                                float(total_functions)) * 100
        return (total_functions, reached_func_count, unreached_func_count,
                reached_percentage, unreached_percentage)

    def resolve_coverage_report_link(self, coverage_url, function_source_file,
                                     lineno, func_name):

        if self.target_lang == "python":
            return self.profiles[0].resolve_coverage_link(
                coverage_url, function_source_file, lineno, func_name)
        elif self.target_lang == "jvm":
            return self.profiles[0].resolve_coverage_link(
                coverage_url, function_source_file, lineno, func_name)
        else:
            return "%s%s.html#L%d" % (coverage_url, function_source_file,
                                      lineno)

    @property
    def target_lang(self):
        """Language the fuzzers are written in"""
        set_of_targets = set()
        for profile in self.profiles:
            set_of_targets.add(profile.target_lang)
        if len(set_of_targets) > 1:
            raise exceptions.AnalysisError(
                "Project has fuzzers with multiple targets")
        return set_of_targets.pop()

    def get_profiles_coverage_files(self) -> List[str]:
        all_coverage_files_used = list()
        for profile in self.profiles:
            if profile.coverage is None:
                continue
            all_coverage_files_used += profile.coverage.coverage_files
        return all_coverage_files_used

    def has_coverage_data(self) -> bool:
        return len(self.get_profiles_coverage_files()) != 0

    def get_complexity_summaries(self) -> Tuple[int, int, int, float, float]:
        """Gets data points summarising cyclomatic complexity across the project,
        including total complexity, the amount of complexity that is statically
        reached and the amount of complexity that is statically unreached.
        """
        complexity_reached, complexity_unreached = self._get_total_complexity()
        total_complexity = complexity_unreached + complexity_reached

        try:
            reached_complexity_percentage = (float(complexity_reached) /
                                             (total_complexity)) * 100.0
        except Exception:
            logger.info("Total complexity is 0")
            reached_complexity_percentage = 0
        try:
            unreached_complexity_percentage = ((float(complexity_unreached) /
                                                (total_complexity)) * 100.0)
        except Exception:
            logger.info("Total complexity is 0")
            unreached_complexity_percentage = 0

        return (total_complexity, complexity_reached, complexity_unreached,
                reached_complexity_percentage, unreached_complexity_percentage)

    def get_direct_parent_list(
        self, target_function: function_profile.FunctionProfile
    ) -> Tuple[List[function_profile.FunctionProfile], List[str]]:
        """
        Search through list of parent functions of the
        target function and return a subset of functions
        in list which is the immediate parent function
        calling the target function.
        """
        result_list = []
        result_name_list = []
        for func_name in target_function.incoming_references:
            if func_name in self.all_functions.keys():
                fd = self.all_functions[func_name]
                if target_function.function_name in fd.functions_called:
                    result_list.append(fd)
                    result_name_list.append(func_name)

        return (result_list, result_name_list)

    def get_function_callpaths(
        self,
        target_function: function_profile.FunctionProfile,
        handled_functions: List[function_profile.FunctionProfile],
    ) -> Tuple[List[List[function_profile.FunctionProfile]], List[List[str]]]:
        """
        Recursively resolve the incoming reference of a function
        profile and build up lists of function callpaths from each
        of the incoming functions to the target function.
        """
        if len(target_function.incoming_references) == 0:
            # Outtermost function
            return ([[]], [[]])

        result_list = []
        result_name_list = []
        for func_name in target_function.incoming_references:
            if func_name in self.all_functions.keys():
                fd = self.all_functions[func_name]
                if fd in handled_functions:
                    continue

                if target_function.function_name in fd.functions_called:
                    handled_functions.append(fd)
                    inner_list, inner_name_list = self.get_function_callpaths(
                        fd, handled_functions)
                    for list in inner_list:
                        list.append(fd)
                        result_list.append(list)
                    for name_list in inner_name_list:
                        name_list.append(fd.function_name)
                        result_name_list.append(name_list)
        return (result_list, result_name_list)

    def write_stats_to_summary_file(self) -> None:
        (total_complexity, complexity_reached, complexity_unreached,
         reached_complexity_percentage,
         unreached_complexity_percentage) = self.get_complexity_summaries()

        (total_functions, reached_func_count, unreached_func_count,
         reached_func_percentage,
         unreached_func_percentage) = self.get_function_summaries()

        covered_funcs = self.get_all_runtime_covered_functions()
        cov_percentage = round(len(covered_funcs) / total_functions, 2) * 100.0

        json_report.add_project_key_value_to_report(
            "stats", {
                "total-complexity": total_complexity,
                "complexity-reached": complexity_reached,
                "complexity-unreached": complexity_unreached,
                "reached-complexity-percentage": reached_complexity_percentage,
                "unreached-complexity-percentage":
                unreached_complexity_percentage,
                'total-functions': total_functions,
                'reached-function-count': reached_func_count,
                'unreached-function-count': unreached_func_count,
                'reached-function-percentage': reached_func_percentage,
                'unreached-function-percentage': unreached_func_percentage,
                'code-coverage-function-count': len(covered_funcs),
                'code-coverage-function-percentage': cov_percentage
            })

    def _set_basefolder(self) -> None:
        """Identifies a common path-prefix amongst source files in. This is
        used to remove locations within a host system to essentially make
        paths as if they were from the root of the source code project.
        """
        all_strs = []
        for f in self.all_functions.values():
            if f.function_source_file == "":
                continue
            if "/usr/include/" in f.function_source_file:
                continue
            all_strs.append(os.path.dirname(f.function_source_file))

        self.basefolder = utils.longest_common_prefix(all_strs) + "/"

    def _get_total_unreached_function_count(self) -> int:
        unreached_function_count = 0
        for fd in self.all_functions.values():
            if fd.hitcount == 0:
                unreached_function_count += 1
        return unreached_function_count

    def _get_total_reached_function_count(self) -> int:
        reached_function_count = 0
        for fd in self.all_functions.values():
            if fd.hitcount != 0:
                reached_function_count += 1
        return reached_function_count

    def _get_total_complexity(self) -> Tuple[int, int]:
        reached_complexity = 0
        unreached_complexity = 0
        for fd in self.all_functions.values():
            if fd.hitcount == 0:
                unreached_complexity += fd.cyclomatic_complexity
            else:
                reached_complexity += fd.cyclomatic_complexity
        return reached_complexity, unreached_complexity
