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
""" Module for loading CFG files """

import os
import sys

def data_file_read_calltree(filename):
    """
    Extracts the calltree of a fuzzer from a .data file.
    This is for C/C++ files
    """
    read_tree = False
    function_call_depths = []

    tmp_function_depths = {
                'depth' : -2,
                'function_calls' : []
            }
    with open(filename, "r") as flog:
        for line in flog:
            line = line.replace("\n", "")
            if read_tree and "======" not in line:
                stripped_line = line.strip().split(" ")

                # Type: {spacing depth} {target filename} {line count}
                if len(stripped_line) == 3:
                    filename = stripped_line[1]
                    linenumber = int(stripped_line[2].replace("linenumber=",""))
                else: 
                    filename = ""
                    linenumber=0

                space_count = len(line) - len(line.lstrip(' '))
                depth = space_count / 2
                curr_node = { 'function_name' : stripped_line[0],
                              'functionSourceFile' : filename,
                              'depth' : depth,
                              'linenumber' : linenumber}

                if tmp_function_depths['depth'] != depth:
                    if tmp_function_depths['depth'] != -2:
                        function_call_depths += list(sorted(tmp_function_depths['function_calls'], key=lambda x: x['linenumber']))
                    tmp_function_depths = {
                                'depth' : depth,
                                'function_calls' : []
                            }
                tmp_function_depths['function_calls'].append(curr_node)

                #function_call_depths.append(curr_node)
            if "====================================" in line:
                read_tree = False
            if "Call tree" in line:
                read_tree = True
        # Add the remaining list of nodes to the overall list.
        function_call_depths += list(sorted(tmp_function_depths['function_calls'], key=lambda x: x['linenumber']))

    return function_call_depths
