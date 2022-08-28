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
import json
import logging

from typing import (
    Any,
    Dict,
    List,
    Optional,
)

from fuzz_introspector import constants
from fuzz_introspector import utils
from fuzz_introspector.datatypes import (
    project_profile,
    fuzzer_profile,
    function_profile,
    branch_profile,
    bug
)
from fuzz_introspector.exceptions import DataLoaderError

logger = logging.getLogger(name=__name__)


def read_fuzzer_data_file_to_profile(
    cfg_file: str,
    language: str
) -> Optional[fuzzer_profile.FuzzerProfile]:
    """
    For a given .data file (CFG) read the corresponding .yaml file
    This is a bit odd way of doing it and should probably be improved.
    """
    logger.info(f" - loading {cfg_file}")
    if not os.path.isfile(cfg_file) or not os.path.isfile(cfg_file + ".yaml"):
        return None

    data_dict_yaml = utils.data_file_read_yaml(cfg_file + ".yaml")

    # Must be  dictionary
    if data_dict_yaml is None or not isinstance(data_dict_yaml, dict):
        return None

    FP = fuzzer_profile.FuzzerProfile(cfg_file, data_dict_yaml, language)

    # Check we have a valid entrypoint
    if "LLVMFuzzerTestOneInput" in FP.all_class_functions:
        return FP

    # Check for python fuzzers. The following assumes the entrypoint
    # currently has "TestOneInput" int its name
    for name in FP.all_class_functions:
        if "TestOneInput" in name:
            return FP

    logger.info("Found no fuzzer entrypoints")
    return None


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
            logger.error(f"Mismatched function name: {func_name}")
            continue
        f = merged_profile.all_functions[func_name]
        f.hitcount += 1

        f.reached_by_fuzzers.append(utils.demangle_cpp_func(func_to_add.function_name))

    # Recompute all analysis that is based on hitcounts in all functions as hitcount has
    # changed for elements in the dictionary.
    logger.info("Updating hitcount-related data")
    for f_profile in merged_profile.all_functions.values():
        cc = 0
        uncovered_cc = 0
        for reached_func_name in f_profile.functions_reached:
            if reached_func_name not in merged_profile.all_functions:
                logger.error(f"Mismatched function name: {reached_func_name}")
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
        raise DataLoaderError(
            "Hitcount did not get set for some reason"
        )

    return merged_profile


def load_all_profiles(
    target_folder: str,
    language: str
) -> List[fuzzer_profile.FuzzerProfile]:
    profiles = []
    data_files = utils.get_all_files_in_tree_with_regex(
        target_folder,
        "fuzzerLogFile.*\.data$"
    )
    logger.info(f" - found {len(data_files)} profiles to load")
    for data_file in data_files:
        profile = read_fuzzer_data_file_to_profile(data_file, language)
        if profile is not None:
            profiles.append(profile)
    return profiles


def try_load_input_bugs() -> List[bug.Bug]:
    """Loads input bugs as list. Returns empty list if none"""
    if not os.path.isfile(constants.INPUT_BUG_FILE):
        return []
    return load_input_bugs(constants.INPUT_BUG_FILE)


def load_input_bugs(bug_file: str) -> List[bug.Bug]:
    input_bugs: List[bug.Bug] = []
    if not os.path.isfile(bug_file):
        return input_bugs

    # Read file line by line
    with open(bug_file, "r") as f:
        data = json.load(f)

    if type(data) != dict:
        return input_bugs

    if "bugs" not in data:
        return input_bugs

    for bug_dict in data["bugs"]:
        try:
            ib = bug.Bug(
                bug_dict['source_file'],
                bug_dict['source_line'],
                bug_dict['function_name'],
                bug_dict['fuzzer_name'],
                bug_dict['description'],
                bug_dict['bug_type']
            )
            input_bugs.append(ib)
        except Exception:
            continue

    return input_bugs


def read_branch_data_file_to_profile(filename: str, bp_dict: Dict[Any, Any]) -> None:
    """
    Loads branch profiles from LLVM pass output yaml file.
    """
    logger.info(f" - loading {filename}")
    if not os.path.isfile(filename):
        return

    data_dict_yaml = utils.data_file_read_yaml(filename)
    if data_dict_yaml is None:
        return

    for elem in data_dict_yaml:
        new_branch = branch_profile.BranchProfile()
        new_branch.assign_from_yaml_elem(elem)
        bp_dict[new_branch.branch_pos] = new_branch


def load_all_branch_profiles(
    target_folder: str
) -> Dict[str, branch_profile.BranchProfile]:
    all_branch_profiles: Dict[str, branch_profile.BranchProfile] = dict()
    data_files = utils.get_all_files_in_tree_with_regex(
        target_folder,
        ".*branchProfile\.yaml$"
    )
    logger.info(f" - found {len(data_files)} branchProfiles to load")
    for data_file in data_files:
        read_branch_data_file_to_profile(data_file, all_branch_profiles)
    return all_branch_profiles
