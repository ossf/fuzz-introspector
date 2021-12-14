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

import os
import sys
import copy
import cxxfilt
import yaml
import fuzz_html
import fuzz_utils

def longest_common_prefix(strs):
    """
    Returns the longest common prefix of all the strings in strs
    """
    if len(strs) == 0:
        return ""
    current = strs[0]
    for i in range(1,len(strs)):
        temp = ""
        if len(current) == 0:
            break
        for j in range(len(strs[i])):
            if j<len(current) and current[j] == strs[i][j]:
                temp+=current[j]
            else:
                break
        current = temp
    return current

def identify_base_folder(merged_profile):
    """
    Identifies a common path-prefix amongst source files in all_function_data
    dictionary. This is used to remove locations within a host system to 
    essentially make paths as if they were from the root of the source code project.
    """
    all_strs = []
    for func in merged_profile.all_functions:
        if func['functionSourceFile'] != "/":
            all_strs.append(func['functionSourceFile'])
    base = longest_common_prefix(all_strs)
    return base

def get_all_files_in_tree_with_suffix(basedir, suffix):
    """
    Returns a list of paths such that each path is to a file with
    the provided suffix. Walks the entire tree of basedir.
    """
    data_files = []
    for root, dirs, files in os.walk(basedir):
        for f in files:
            if f.endswith(suffix):
                data_files.append(os.path.join(root, f))
    return data_files


def demangle_cpp_func(funcname):
    try:
        demangled = cxxfilt.demangle(funcname.replace(" ",""))
        return demangled
    except:
        return funcname

