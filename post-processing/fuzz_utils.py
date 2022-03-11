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

import logging
import cxxfilt
import os
import re
from typing import (
    Any,
    List,
    Dict,
)
import yaml

l = logging.getLogger(name=__name__)


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


def safe_decode(data) -> str:
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
                l.info("f: %s -- matches regex: %s" % f, regex_str)
                data_files.append(os.path.join(root, f))
    return data_files


def data_file_read_yaml(filename: str) -> Dict[Any, Any]:
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
            data_dict = yaml.safe_load(stream)
            return data_dict
        except yaml.YAMLError:
            return None


def demangle_cpp_func(funcname: str) -> str:
    try:
        demangled = cxxfilt.demangle(funcname.replace(" ", ""))
        return demangled
    except Exception:
        return funcname


# fuzzer files can only have a name using limited characters
def scan_executables_for_fuzz_introspector_logs(exec_dir: str):
    regex = '[%s]{%d,}' % (r"A-Za-z0-9_-", 10)
    fuzzer_log_file_pattern = re.compile(regex)
    if not os.path.isdir(exec_dir):
        return []
    executable_to_fuzz_reports = []
    for f in os.listdir(exec_dir):
        full_path = os.path.join(exec_dir, f)
        if os.access(full_path, os.X_OK) and os.path.isfile(full_path):
            print("File: %s is executable" % full_path)
            # Read all of the strings in this file
            with open(full_path, "rb") as fp:
                all_ascii_data = fp.read().decode('ascii', 'ignore')
                for found_str in fuzzer_log_file_pattern.findall(all_ascii_data):
                    if "fuzzerLogFile" in found_str:
                        print(found_str)
                        executable_to_fuzz_reports.append({
                            'executable_path': full_path,
                            'fuzzer_log_file': found_str
                        })
    return executable_to_fuzz_reports
