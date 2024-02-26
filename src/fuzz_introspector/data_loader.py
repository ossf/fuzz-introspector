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
import json
import logging
import multiprocessing

from typing import (
    Any,
    Dict,
    List,
    Optional,
)

from fuzz_introspector import constants
from fuzz_introspector import utils
from fuzz_introspector.datatypes import (fuzzer_profile, bug)

logger = logging.getLogger(name=__name__)


def read_fuzzer_data_file_to_profile(
        cfg_file: str,
        language: str) -> Optional[fuzzer_profile.FuzzerProfile]:
    """
    For a given .data file (CFG) read the corresponding .yaml file
    This is a bit odd way of doing it and should probably be improved.
    """
    logger.info(f" - loading {cfg_file}")
    if not os.path.isfile(cfg_file) or not os.path.isfile(cfg_file + ".yaml"):
        return None

    data_dict_yaml = utils.data_file_read_yaml(cfg_file + ".yaml")
    logger.info(f"Finished loading {cfg_file}")

    # Must be  dictionary
    if data_dict_yaml is None or not isinstance(data_dict_yaml, dict):
        return None

    profile = fuzzer_profile.FuzzerProfile(cfg_file, data_dict_yaml, language)

    if not profile.has_entry_point():
        logger.info("Found no entrypoints")
        return None
    logger.info("Returning profile")
    return profile


def _load_profile(data_file: str, language: str, manager, semaphore=None):
    """Internal function used for multithreaded profile loading"""
    if semaphore is not None:
        semaphore.acquire()

    profile = read_fuzzer_data_file_to_profile(data_file, language)
    if profile is not None:
        manager[data_file] = profile

    if semaphore is not None:
        semaphore.release()


def load_all_debug_files(target_folder: str):
    """Loads all .debug_info files"""
    debug_info_files = utils.get_all_files_in_tree_with_regex(
        target_folder, ".*debug_info$")
    for file in debug_info_files:
        print("debug info file: %s" % (file))
    return debug_info_files


def find_all_debug_all_types_files(target_folder: str):
    """Loads all .debug_info files"""
    debug_info_files = utils.get_all_files_in_tree_with_regex(
        target_folder, ".*debug_all_types$")
    for file in debug_info_files:
        print("debug info file: %s" % (file))
    return debug_info_files


def load_all_profiles(
        target_folder: str,
        language: str,
        parallelise: bool = True) -> List[fuzzer_profile.FuzzerProfile]:
    """Loads all profiles in target_folder in a multi-threaded manner"""

    if language == "jvm":
        # Java targets tend to be quite large, so we try to avoid memory
        # exhaustion here.
        semaphore_count = 3
    else:
        semaphore_count = 6

    profiles = []
    data_files = utils.get_all_files_in_tree_with_regex(
        target_folder, "fuzzerLogFile.*\.data$")
    logger.info(f" - found {len(data_files)} profiles to load")
    if parallelise:
        manager = multiprocessing.Manager()
        semaphore = multiprocessing.Semaphore(semaphore_count)
        return_dict = manager.dict()
        jobs = []
        for data_file in data_files:
            p = multiprocessing.Process(target=_load_profile,
                                        args=(data_file, language, return_dict,
                                              semaphore))
            jobs.append(p)
            p.start()
        for proc in jobs:
            proc.join()

        for k, v in return_dict.items():
            profiles.append(v)
    else:
        return_dict_gen: Dict[Any, Any] = dict()
        for data_file in data_files:
            _load_profile(data_file, language, return_dict_gen, None)
        for k, v in return_dict_gen.items():
            profiles.append(v)

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

    if not isinstance(data, dict):
        return input_bugs

    if "bugs" not in data:
        return input_bugs

    for bug_dict in data["bugs"]:
        try:
            ib = bug.Bug(bug_dict['source_file'], bug_dict['source_line'],
                         bug_dict['function_name'], bug_dict['fuzzer_name'],
                         bug_dict['description'], bug_dict['bug_type'])
            input_bugs.append(ib)
        except Exception:
            continue

    return input_bugs
