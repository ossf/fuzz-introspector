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

import os
import yaml
import cxxfilt

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

def data_file_read_yaml(filename):
    """
    Reads a file as a yaml file. This is used to load data
    from fuzz-introspectors compiler plugin output.
    """
    with open(filename, 'r') as stream:
        try:
            data_dict = yaml.safe_load(stream)
            return data_dict
        except yaml.YAMLError as exc:
            return None

def demangle_cpp_func(funcname):
    try:
        demangled = cxxfilt.demangle(funcname.replace(" ",""))
        return demangled
    except:
        return funcname
