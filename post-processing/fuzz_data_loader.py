# Copyright 2021 Fuzz Introspector Authors
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
"""Reads the data output from the fuzz introspector LLVM plugin."""

import os
import copy
import logging

from typing import (
    Any,
    Dict,
    List,
    Optional,
    Set,
    Tuple,
)

import fuzz_cfg_load
import fuzz_cov_load
import fuzz_utils

logger = logging.getLogger(name=__name__)


class FunctionProfile:
    """
    Class for storing information about a given Function
    """
    def __init__(self, function_name):
        self.function_name = function_name
        self.function_source_file = None
        self.linkage_type = None
        self.function_linenumber = None
        self.return_type = None
        self.arg_count = None
        self.arg_types = None
        self.arg_names = None
        self.bb_count = None
        self.i_count = None
        self.hitcount = 0
        self.reached_by_fuzzers = list()
        self.edge_count = None
        self.cyclomatic_complexity = None
        self.functions_reached = None
        self.function_uses = None
        self.function_depth = None
        self.incoming_references = list()
        self.constants_touched = list()
        self.new_unreached_complexity = None
        self.total_cyclomatic_complexity = None

    def migrate_from_yaml_elem(self, elem):
        self.function_name = elem['functionName']
        self.function_source_file = elem['functionSourceFile']
        self.linkage_type = elem['linkageType']
        self.function_linenumber = elem['functionLinenumber']
        self.return_type = elem['returnType']
        self.arg_count = elem['argCount']
        self.arg_types = elem['argTypes']
        self.arg_names = elem['argNames']
        self.bb_count = elem['BBCount']
        self.i_count = elem['ICount']
        self.edge_count = elem['EdgeCount']
        self.cyclomatic_complexity = elem['CyclomaticComplexity']
        self.functions_reached = elem['functionsReached']
        self.function_uses = elem['functionUses']
        self.function_depth = elem['functionDepth']
        self.constants_touched = elem['constantsTouched']


class FuzzerProfile:
    """
    Class for storing information about a given Fuzzer.

    This class essentially holds data corresponding to the output of run of the LLVM
    plugin. That means, the output from the plugin for a single fuzzer.
    """
    def __init__(self, filename: str, data_dict_yaml: Dict[Any, Any]):
        self.introspector_data_file = filename
        self.function_call_depths = fuzz_cfg_load.data_file_read_calltree(filename)
        self.fuzzer_source_file = data_dict_yaml['Fuzzer filename']
        self.binary_executable = None
        self.coverage = None
        self.file_targets: Dict[str, Set[str]] = dict()

        # Create a list of all the functions.
        self.all_class_functions = dict()
        for elem in data_dict_yaml['All functions']['Elements']:
            # Check if there is normalisation issue and log if so
            if "." in elem['functionName']:
                split_name = elem['functionName'].split(".")
                if split_name[-1].isnumeric():
                    logger.info(
                        "We may have a non-normalised function name: %s" % elem['functionName']
                    )

            func_profile = FunctionProfile(elem['functionName'])
            func_profile.migrate_from_yaml_elem(elem)
            self.all_class_functions[func_profile.function_name] = func_profile

    def refine_paths(self, basefolder: str) -> None:
        """
        Removes the project_profile's basefolder from source paths in a given profile.
        """
        # Only do this is basefolder is not wrong
        if basefolder == "/":
            return

        self.fuzzer_source_file = self.fuzzer_source_file.replace(basefolder, "")

        if self.function_call_depths is not None:
            all_callsites = fuzz_cfg_load.extract_all_callsites(self.function_call_depths)
            for cs in all_callsites:
                cs.dst_function_source_file = cs.dst_function_source_file.replace(basefolder, "")

            new_dict = {}
            for key in self.file_targets:
                new_dict[key.replace(basefolder, "")] = self.file_targets[key]
            self.file_targets = new_dict

    def set_all_reached_functions(self) -> None:
        """
        sets self.functions_reached_by_fuzzer to all functions reached
        by LLVMFuzzerTestOneInput
        """
        self.functions_reached_by_fuzzer = (self
                                            .all_class_functions["LLVMFuzzerTestOneInput"]
                                            .functions_reached)

    def reaches(self, func_name: str) -> bool:
        return func_name in self.functions_reached_by_fuzzer

    def correlate_executable_name(self, correlation_dict):
        for elem in correlation_dict['pairings']:
            if os.path.basename(self.introspector_data_file) in "%s.data" % elem['fuzzer_log_file']:
                self.binary_executable = "%s" % elem['executable_path']
                logger.info("Correlated %s with %s" % (
                    os.path.basename(self.introspector_data_file),
                    "%s.data" % elem['fuzzer_log_file']))

    def get_key(self):
        """
        Returns the "key" we use to identify this Fuzzer profile.
        """
        if self.binary_executable is not None:
            return os.path.basename(self.binary_executable)

        return self.fuzzer_source_file

    def set_all_unreached_functions(self):
        """
        sets self.functions_unreached_by_fuzzer to all functiosn in self.all_class_functions
        that are not in self.functions_reached_by_fuzzer
        """
        self.functions_unreached_by_fuzzer = [
            f.function_name for f
            in self.all_class_functions.values()
            if f.function_name not in self.functions_reached_by_fuzzer
        ]

    def load_coverage(self, target_folder: str) -> None:
        """
        Load coverage data for this profile
        """
        self.coverage = fuzz_cov_load.llvm_cov_load(
            target_folder,
            self.get_target_fuzzer_filename())

    def get_function_coverage(self,
                              function_name: str,
                              should_normalise: bool = False) -> List[Tuple[int, int]]:
        """
        Get the tuples reflecting coverage map of a given function
        """
        if self.coverage is None:
            return []
        if not should_normalise:
            if function_name not in self.coverage.covmap:
                return []
            return self.coverage.covmap[function_name]
        # should_normalise
        for funcname in self.coverage.covmap:
            normalised_funcname = fuzz_utils.demangle_cpp_func(fuzz_utils.normalise_str(funcname))
            if normalised_funcname == function_name:
                return self.coverage.covmap[funcname]

        # In case of errs return empty list
        return []

    def get_target_fuzzer_filename(self) -> str:
        return self.fuzzer_source_file.split("/")[-1].replace(".cpp", "").replace(".c", "")

    def get_file_targets(self) -> None:
        """
        Sets self.file_targets to be a dictionarty of string to string.
        Each key in the dictionary is a filename and the corresponding value is
        a set of strings containing strings which are the names of the functions
        in the given file that are reached by the fuzzer.
        """
        if self.function_call_depths is not None:
            all_callsites = fuzz_cfg_load.extract_all_callsites(self.function_call_depths)
            for cs in all_callsites:
                if cs.dst_function_source_file.replace(" ", "") == "":
                    continue
                if cs.dst_function_source_file not in self.file_targets:
                    self.file_targets[cs.dst_function_source_file] = set()
                self.file_targets[cs.dst_function_source_file].add(cs.dst_function_name)

    def get_total_basic_blocks(self) -> None:
        """
        sets self.total_basic_blocks to the sym of basic blocks of all the functions
        reached by this fuzzer.
        """
        total_basic_blocks = 0
        for func in self.functions_reached_by_fuzzer:
            fd = self.all_class_functions[func]
            total_basic_blocks += fd.bb_count
        self.total_basic_blocks = total_basic_blocks

    def get_total_cyclomatic_complexity(self) -> None:
        """
        sets self.total_cyclomatic_complexity to the sum of cyclomatic complexity
        of all functions reached by this fuzzer.
        """
        self.total_cyclomatic_complexity = 0
        for func in self.functions_reached_by_fuzzer:
            fd = self.all_class_functions[func]
            self.total_cyclomatic_complexity += fd.cyclomatic_complexity

    def accummulate_profile(self, target_folder: str) -> None:
        """
        Triggers various analyses on the data of the fuzzer. This is used after a
        profile has been initialised to generate more interesting data.
        """
        self.set_all_reached_functions()
        self.set_all_unreached_functions()
        self.load_coverage(target_folder)
        self.get_file_targets()
        self.get_total_basic_blocks()
        self.get_total_cyclomatic_complexity()

    def get_cov_uncovered_reachable_funcs(self):
        if self.coverage is None:
            return None

        uncovered_funcs = []
        for funcname in self.functions_reached_by_fuzzer:
            if len(self.get_function_coverage(funcname)) == 0:
                uncovered_funcs.append(funcname)
        return uncovered_funcs

    def get_cov_metrics(self,
                        funcname: str) -> Tuple[Optional[int], Optional[int], Optional[float]]:
        if self.coverage is None:
            return None, None, None
        try:
            total_func_lines, hit_lines = self.coverage.get_hit_summary(funcname)
            hit_percentage = (hit_lines / total_func_lines) * 100.0
            return total_func_lines, hit_lines, hit_percentage
        except Exception:
            return None, None, None


class MergedProjectProfile:
    """
    Class for storing information about all fuzzers combined in a given project.

    This means, it contains data for all fuzzers in a given project, and digests
    the manner in a way that makes sense from a project-scope perspective. For
    example, it does project-wide analysis of reachable/unreachable functions by
    digesting data from all the fuzzers in the project.
    """
    def __init__(self, profiles: List[FuzzerProfile]):
        self.name = None
        self.profiles = profiles
        self.all_functions: Dict[str, FunctionProfile] = dict()
        self.unreached_functions = set()
        self.functions_reached = set()

        logger.info("Creating merged profile of %d profiles" % len(self.profiles))
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
        excluded_functions = {
            "sanitizer", "llvm"
        }
        for profile in profiles:
            for fd in profile.all_class_functions.values():
                # continue if the function is to be excluded
                if len([ef for ef in excluded_functions if ef in fd.function_name]) != 0:
                    continue

                # populate hitcount and reached_by_fuzzers and whether it has been handled already
                for fuzzer_profile in profiles:
                    if fuzzer_profile.reaches(fd.function_name):
                        fd.hitcount += 1
                        fd.reached_by_fuzzers.append(fuzzer_profile.get_key())
                    if fd.function_name not in self.all_functions:
                        self.all_functions[fd.function_name] = fd

        # Gather complexity information about each function
        logger.info("Gathering complexity and incoming references of each function")
        for fp_obj in self.all_functions.values():
            total_cyclomatic_complexity = 0
            total_new_complexity = 0

            for reached_func_name in fp_obj.functions_reached:
                if reached_func_name not in self.all_functions:
                    logger.error("Mismatched function name: %s" % reached_func_name)
                    continue
                reached_func_obj = self.all_functions[reached_func_name]
                reached_func_obj.incoming_references.append(fp_obj.function_name)
                total_cyclomatic_complexity += reached_func_obj.cyclomatic_complexity
                if reached_func_obj.hitcount == 0:
                    total_new_complexity += reached_func_obj.cyclomatic_complexity
            if fp_obj.hitcount == 0:
                fp_obj.new_unreached_complexity = (
                    total_new_complexity
                    + fp_obj.cyclomatic_complexity
                )
            else:
                fp_obj.new_unreached_complexity = total_new_complexity
            fp_obj.total_cyclomatic_complexity = (
                total_cyclomatic_complexity
                + fp_obj.cyclomatic_complexity
            )

        # Accumulate run-time coverage mapping
        self.runtime_coverage = fuzz_cov_load.CoverageProfile()
        for profile in profiles:
            if profile.coverage is None:
                continue
            for func_name in profile.coverage.functions_hit:
                if func_name not in self.runtime_coverage.covmap:
                    self.runtime_coverage.functions_hit.add(func_name)
            for func_name in profile.coverage.covmap:
                if func_name not in self.runtime_coverage.covmap:
                    self.runtime_coverage.covmap[func_name] = profile.coverage.covmap[func_name]
                else:
                    # Merge by picking highest line numbers. Here we can assume they coverage
                    # maps have the same number of elements with the same line numbers but
                    # different hit counts.
                    new_line_counts = list()
                    for idx1 in range(len(self.runtime_coverage.covmap[func_name])):
                        try:
                            ln1, ht1 = self.runtime_coverage.covmap[func_name][idx1]
                            ln2, ht2 = profile.coverage.covmap[func_name][idx1]
                        except Exception:
                            ln1, ht1 = self.runtime_coverage.covmap[func_name][idx1]
                            ln2, ht2 = self.runtime_coverage.covmap[func_name][idx1]
                        # It may be that line numbers are not the same for the same function
                        # name across different fuzzers.
                        # This *could* actually happen, and will often (almost always) happen for
                        # LLVMFuzzerTestOneInput. In this case we just gracefully
                        # continue and ignore issues.
                        if ln1 != ln2:
                            logger.error("Line numbers are different in the same function")
                            continue
                        new_line_counts.append((ln1, max(ht1, ht2)))
                    self.runtime_coverage.covmap[func_name] = new_line_counts
        self.set_basefolder()
        logger.info("Completed creationg of merged profile")

    def get_total_complexity(self) -> Tuple[int, int]:
        reached_complexity = 0
        unreached_complexity = 0
        for fd in self.all_functions.values():
            if fd.hitcount == 0:
                unreached_complexity += fd.cyclomatic_complexity
            else:
                reached_complexity += fd.cyclomatic_complexity
        return reached_complexity, unreached_complexity

    def get_total_unreached_function_count(self) -> int:
        unreached_function_count = 0
        for fd in self.all_functions.values():
            if fd.hitcount == 0:
                unreached_function_count += 1
        return unreached_function_count

    def get_total_reached_function_count(self) -> int:
        reached_function_count = 0
        for fd in self.all_functions.values():
            if fd.hitcount != 0:
                reached_function_count += 1
        return reached_function_count

    def get_all_runtime_covered_functions(self):
        all_covered_functions = []
        for funcname in self.runtime_coverage.covmap:
            all_covered_functions.append(funcname)
        return all_covered_functions

    def get_function_reach_percentage(self) -> float:
        total_functions = (
            float(self.get_total_unreached_function_count()
                  + self.get_total_reached_function_count())
        )
        reached_percentage = (
            float(self.get_total_reached_function_count() / total_functions)
            * 100.0
        )
        return reached_percentage

    def get_function_summaries(self) -> Tuple[int, int, int, float, float]:
        reached_func_count = self.get_total_reached_function_count()
        unreached_func_count = self.get_total_unreached_function_count()
        total_functions = reached_func_count + unreached_func_count
        reached_percentage = (float(reached_func_count) / float(total_functions)) * 100
        unreached_percentage = (float(unreached_func_count) / float(total_functions)) * 100
        return (
            total_functions,
            reached_func_count,
            unreached_func_count,
            reached_percentage,
            unreached_percentage
        )

    def get_complexity_summaries(self) -> Tuple[int, int, int, float, float]:

        complexity_reached, complexity_unreached = self.get_total_complexity()
        total_complexity = complexity_unreached + complexity_reached

        reached_complexity_percentage = (float(complexity_reached) / (total_complexity)) * 100.0
        unreached_complexity_percentage = (float(complexity_unreached) / (total_complexity)) * 100.0

        return (
            total_complexity,
            complexity_reached,
            complexity_unreached,
            reached_complexity_percentage,
            unreached_complexity_percentage
        )

    def set_basefolder(self) -> None:
        """
        Identifies a common path-prefix amongst source files in
        This is used to remove locations within a host system to
        essentially make paths as if they were from the root of the source code project.
        """
        all_strs = []
        for f in self.all_functions.values():
            if f.function_source_file == "/":
                continue
            if "/usr/include/" in f.function_source_file:
                continue
            all_strs.append(f.function_source_file)

        self.basefolder = fuzz_utils.longest_common_prefix(all_strs)


def read_fuzzer_data_file_to_profile(filename: str) -> Optional[FuzzerProfile]:
    """
    For a given .data file (CFG) read the corresponding .yaml file
    This is a bit odd way of doing it and should probably be improved.
    """
    logger.info(" - loading %s" % filename)
    if not os.path.isfile(filename) or not os.path.isfile(filename + ".yaml"):
        return None

    data_dict_yaml = fuzz_utils.data_file_read_yaml(filename + ".yaml")
    if data_dict_yaml is None:
        return None

    FP = FuzzerProfile(filename, data_dict_yaml)
    if "LLVMFuzzerTestOneInput" not in FP.all_class_functions:
        return None

    return FP


def add_func_to_reached_and_clone(merged_profile_old: MergedProjectProfile,
                                  func_to_add: FunctionProfile) -> MergedProjectProfile:
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
            logger.error("Mismatched function name: %s" % func_name)
            continue
        f = merged_profile.all_functions[func_name]
        f.hitcount += 1

        f.reached_by_fuzzers.append(fuzz_utils.demangle_cpp_func(func_to_add.function_name))

    # Recompute all analysis that is based on hitcounts in all functions as hitcount has
    # changed for elements in the dictionary.
    logger.info("Updating hitcount-related data")
    for f_profile in merged_profile.all_functions.values():
        cc = 0
        uncovered_cc = 0
        for reached_func_name in f_profile.functions_reached:
            if reached_func_name not in merged_profile.all_functions:
                logger.error("Mismatched function name: %s" % reached_func_name)
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

    return merged_profile


def load_all_profiles(target_folder: str) -> List[FuzzerProfile]:
    profiles = []
    data_files = fuzz_utils.get_all_files_in_tree_with_regex(
        target_folder,
        "fuzzerLogFile.*\.data$"
    )
    logger.info(" - found %d profiles to load" % len(data_files))
    for data_file in data_files:
        profile = read_fuzzer_data_file_to_profile(data_file)
        if profile is not None:
            profiles.append(profile)
    return profiles
