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
""" Utility functions """

import cxxfilt
import logging
import json
import os
import re
import yaml

from typing import (
    Any,
    List,
    Dict,
    Optional,
)

import fuzz_constants

logger = logging.getLogger(name=__name__)


def longest_common_prefix(strs: List[str]) -> str:
    """
    Returns the longest common prefix of all the strings in strs
    """
    if len(strs) == 0:
        return ""
    current = strs[0]
    for i in range(1, len(strs)):
        temp = ""
        if len(current) == 0:
            break
        for j in range(len(strs[i])):
            if j < len(current) and current[j] == strs[i][j]:
                temp += current[j]
            else:
                break
        current = temp
    return current


def normalise_str(s1: str) -> str:
    return s1.replace("\t", "").replace("\r", "").replace("\n", "").replace(" ", "")


def safe_decode(data) -> Optional[str]:
    try:
        return data.decode()
    except Exception:
        None
    try:
        return data.decode('unicode-escape')
    except Exception:
        None
    return None


def get_all_files_in_tree_with_regex(basedir: str, regex_str: str) -> List[str]:
    """
    Returns a list of paths such that each path is to a file with
    the provided suffix. Walks the entire tree of basedir.
    """
    r = re.compile(regex_str)
    data_files = []
    for root, dirs, files in os.walk(basedir):
        for f in files:
            if r.match(f):
                logger.info("f: %s -- matches regex: %s" % (f, regex_str))
                data_files.append(os.path.join(root, f))
    return data_files


def data_file_read_yaml(filename: str) -> Optional[Dict[Any, Any]]:
    """
    Reads a file as a yaml file. This is used to load data
    from fuzz-introspectors compiler plugin output.
    """
    if filename == "":
        return None
    if not os.path.isfile(filename):
        return None

    with open(filename, 'r') as stream:
        try:
            data_dict: Dict[Any, Any] = yaml.safe_load(stream)
            return data_dict
        except yaml.YAMLError:
            return None


def demangle_cpp_func(funcname: str) -> str:
    try:
        demangled: str = cxxfilt.demangle(funcname.replace(" ", ""))
        return demangled
    except Exception:
        return funcname


# fuzzer files can only have a name using limited characters
def scan_executables_for_fuzz_introspector_logs(
    exec_dir: str
) -> List[Dict[str, str]]:
    regex = '[%s]{%d,}' % (r"A-Za-z0-9_-", 10)
    fuzzer_log_file_pattern = re.compile(regex)
    if not os.path.isdir(exec_dir):
        return []
    executable_to_fuzz_reports = []
    for f in os.listdir(exec_dir):
        full_path = os.path.join(exec_dir, f)
        if os.access(full_path, os.X_OK) and os.path.isfile(full_path):
            logger.info("File: %s is executable" % full_path)
            # Read all of the strings in this file
            with open(full_path, "rb") as fp:
                all_ascii_data = fp.read().decode('ascii', 'ignore')
                for found_str in fuzzer_log_file_pattern.findall(all_ascii_data):
                    if "fuzzerLogFile" in found_str:
                        logger.info("Found match %s" % found_str)
                        executable_to_fuzz_reports.append({
                            'executable_path': full_path,
                            'fuzzer_log_file': found_str
                        })
    return executable_to_fuzz_reports


def approximate_python_coverage_files(src1: str, src2: str) -> bool:
    logger.info(f"Approximating {src1} to {src2}")
    # Remove prefixed .....
    src1 = src1.lstrip(".")

    # Generate list of potential candidates
    possible_candidates = []
    splits = src1.split(".")
    curr_str = ""
    for s2 in splits:
        curr_str = curr_str + s2
        possible_candidates.append(curr_str + ".py")
        curr_str = curr_str + "/"

    # Start from backwards to find te longest possible candidate
    target = None
    for candidate in reversed(possible_candidates):
        if src2.endswith(candidate):
            # ensure the entire filename is matched in the event of not slashes
            if "/" not in candidate:
                if not src2.split("/")[-1] == candidate:
                    continue
            target = candidate
            break

    if target is not None:
        logger.info(f"Found target {target}")
        return True
    else:
        logger.info("Found no target")
        return False


def write_to_summary_file(fuzzer: str, key: str, value: Any) -> None:
    """Writes a key value pair to summary file, for a given fuzzer
    key. If the fuzzer does not exist as top key in the summary file
    then it is created"""

    if not os.path.isfile(fuzz_constants.SUMMARY_FILE):
        json_data = dict()
    else:
        json_fd = open(fuzz_constants.SUMMARY_FILE)
        json_data = json.load(json_fd)
        json_fd.close()

    if fuzzer not in json_data:
        json_data[fuzzer] = dict()

    json_data[fuzzer][key] = value

    with open(fuzz_constants.SUMMARY_FILE, 'w') as json_file:
        json.dump(json_data, json_file)


def get_target_coverage_url(
    coverage_url: str,
    target_name: str,
    target_lang: str
) -> str:
    """
    This function changes overall coverage URL to per-target coverage URL. Like:
        https://storage.googleapis.com/oss-fuzz-coverage/<project>/reports/<report-date>/linux
        to
        https://storage.googleapis.com/oss-fuzz-coverage/<project>/reports-by-target/<report-date>/<target-name>/linux
    """
    logger.info(f"Extracting coverage for {coverage_url} -- {target_name}")
    if os.environ.get('FUZZ_INTROSPECTOR'):
        if target_lang == "c-cpp":
            return coverage_url.replace(
                "reports", "reports-by-target"
            ).replace("linux", f"{target_name}/linux")
        else:
            return coverage_url
    else:  # (TODO) This is temporary for local runs.
        return coverage_url
