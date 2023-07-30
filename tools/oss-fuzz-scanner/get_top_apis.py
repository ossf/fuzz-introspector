# Copyright 2023 Fuzz Introspector Authors
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
import json
import cxxfilt
import scanner


def count_depth_from_fuzzer(line):
    spaces_at_start = 0
    for c in line:
        if c == ' ':
            spaces_at_start += 1
        else:
            break
    return int(spaces_at_start / 2)


def get_filename_from_line(line):
    retval = line.split(" ")[-2]
    if retval != '':
        return retval
    raise Exception(
        "No file found, this could be because it's a system function or deps with no file info"
    )


def get_function_from_line(line):
    retval = line.split(" ")[-3]
    if retval != '':
        return retval
    raise Exception(
        "No function found. This should not happen for real call lines, but may happen for metadata"
    )


def get_mappings_for_project(project_name):
    scanner.download_project_introspector_artifacts(project_name, '.', -1)
    results = []

    # Scan for files downloaded
    for datafile in os.listdir("."):
        src_file = None
        dst_files = []
        dst_fnames = []
        if datafile.endswith(".data"):
            #print(datafile)
            with open(datafile, "r") as f:
                for line in f.read().split("\n"):
                    # Skip end of file line
                    if "============" in line:
                        continue

                    # get depth of call from fuzzer entry
                    d = count_depth_from_fuzzer(line)

                    # skip those above 1
                    if d > 1:
                        continue
                    # Get the filename of the call
                    try:
                        filename = get_filename_from_line(line)
                        fname = cxxfilt.demangle(get_function_from_line(line))
                    except:
                        continue

                    if d == 0:
                        # LLVMFuzzerTestOneInput
                        src_file = filename
                    else:
                        dst_files.append(filename)
                        dst_fnames.append(fname)

            #print("Src: %s"%(src_file))
            #print(dst_files)
            #print(dst_fnames)
            results.append({'fuzzer_src': src_file, 'dst_function_names': dst_fnames})

    # Clean up the downloaded files
    for f2 in os.listdir("."):
        if f2.endswith(".yaml") or f2.endswith(".data") or f2.endswith(
                ".covreport"):
            os.remove(f2)
    return results


ALL_PROJECTS = ['htslib', 'tinyxml2', 'leveldb', 'c-ares']
for project_name in ALL_PROJECTS:
    print(project_name)
    for fuzzer_result in get_mappings_for_project(project_name):
        print(json.dumps(fuzzer_result))
