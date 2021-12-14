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
import sys
import copy
import cxxfilt
import yaml
import fuzz_html
import fuzz_utils

debug = False
BASE_DIR = None

def data_file_read_all_function_data_yaml(filename):
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

def data_file_read_calltree(filename):
    """
    Extracts the calltree of a fuzzer from a .data file.
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
        tmp_function_depths['function_calls'] += list(sorted(tmp_function_depths['function_calls'], key=lambda x: x['linenumber']))
    return function_call_depths

def extract_functions_covered(target_dir, target_name=None):
    """
    Reads all of the functions hit across all of the covreport files.
    This is a bit over-approximating in that we dont actually find coverage
    on a per-fuzzer basis, which is what we shuold. 
    The difficulty in finding coverage on a per-fuzzer basis is correlating
    binary files to the introspection done a compile time. Files could be
    moved around and remaned, so we need some mechanism that looks at the 
    internals, e.g. file name and location of LLVMFuzzerTestOneInput. 
    But, we wait a bit with this.
    """
    coverage_reports = fuzz_utils.get_all_files_in_tree_with_suffix(target_dir, ".covreport")
    functions_hit = set()
    coverage_map = dict()

    # Check if there is a meaningful profile and if not, we need to use all.
    found_name = False
    if target_name != None:
        for pf in coverage_reports:
            if target_name in pf:
                found_name = True

    for profile_file in coverage_reports:
        # If only coverage from a specific report should be used then filter
        # here. Otherwise, include coverage from everybody.
        if found_name and target_name not in profile_file:
            continue

        with open(profile_file, "r") as pf:
            curr_func = None
            for line in pf:
                stripped_line = line.replace("\n","")
                if len(stripped_line) > 0 and stripped_line[-1] == ":" and "|" not in stripped_line:
                    #print("We got a function definition: %s"%(line.replace("n","")))
                    if len(line.split(":")) == 3:
                        curr_func = stripped_line.split(":")[1].replace(" ","").replace(":","")
                    else:
                        curr_func = stripped_line.replace(" ","").replace(":","")
                    coverage_map[curr_func] = list()
                if curr_func != None and "|" in line:
                    #print("Function: %s has line: %s --- %s"%(curr_func, line.replace("\n",""), str(line.split("|"))))
                    line_number = int(line.split("|")[0])
                    try:
                        # write out numbers e.g. 1.2k into 1200
                        hit_times = int(line.split("|")[1].replace("k","00").replace(".",""))
                    except:
                        hit_times = 0
                    coverage_map[curr_func].append((line_number, hit_times))
                    #print("\tLine %d - hit times: %d"%(line_number, hit_times))

                # We should now normalise the potential function name
                if not stripped_line.endswith(":"):
                    continue
                fname = stripped_line
                if ".cpp" in fname:
                    fname = fname.split(".cpp")[-1].replace(":","")
                    fname = demangle_cpp_func(fname)
                elif ".c" in fname:
                    fname = fname.split(".c")[-1].replace(":","")
                fname = fname.replace(":", "")
                functions_hit.add(fname)
    #for fh in functions_hit:
    #    print("Function: %s"%(fh))
    return functions_hit, coverage_map

def longestCommonPrefix(strs):
    """
    :type strs: List[str]
    :rtype: str
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

def refine_paths(merged_profile):
    """
    Identify the longest common prefix amongst source files in all_function_data
    and remove this from their path.
    """
    global BASE_DIR
    # Find the root of the files to not add unnesecary stuff.
    base = fuzz_utils.identify_base_folder(merged_profile)
    BASE_DIR = base
    #print("Base: %s"%(base))
    
    # Now clear up all source file paths
    #for func in function_dict['All functions']['Elements']:
    for func in merged_profile['all_function_data']:
        if func['functionSourceFile'] != "/":
            func['functionSourceFile'] = func['functionSourceFile'].replace(base, "")

class FuzzerProfile:
    """
    Class for storing information about a given Fuzzer
    """
    def __init__(self, filename, data_dict_yaml):
        self.fuzzer_information = dict()

        # Read data about all functions
        data_dict = dict()
        self.function_call_depths = data_file_read_calltree(filename)
        self.fuzzer_information =  { 'functionSourceFile' : data_dict_yaml['Fuzzer filename'] }
        #self.function_call_depths = function_call_depths
        self.all_function_data = data_dict_yaml['All functions']['Elements']
        self.funcsReachedByFuzzer = None


    def set_all_reached_functions(self):
        self.funcsReachedByFuzzer = list()
        #for func in profile['all_function_data']:
        for func in self.all_function_data:
            if func["functionName"] == "LLVMFuzzerTestOneInput":
                self.funcsReachedByFuzzer = func['functionsReached']
        #return funcsReachedByFuzzer
        if self.funcsReachedByFuzzer == None:
            self.funcsReachedByFuzzer = list()


    def set_all_unreached_functions(self):
        self.funcsUnreachedByFuzzer = list()
        for func in self.all_function_data:
            in_fuzzer = False
            for func_name2 in self.funcsReachedByFuzzer:
                if func_name2 == func['functionName']:
                    in_fuzzer = True
            if not in_fuzzer:
                self.funcsUnreachedByFuzzer.append(func['functionName'])
        #return funcsUnreachedByFuzzer

    def correlate_runtime_coverage_with_reachability(self, target_folder):
        # Merge any runtime coverage data that we may have to correlate
        # reachability and runtime coverage information.
        #print("Finding coverage")
        tname = self.fuzzer_information['functionSourceFile'].split("/")[-1].replace(".cpp","").replace(".c","")
        functions_hit, coverage_map = extract_functions_covered(target_folder, tname)
        if tname != None:
            self.coverage = dict()
            self.coverage['functions-hit'] = functions_hit
            self.coverage['coverage-map'] = coverage_map

    def get_file_targets(self):
        filenames = set()
        file_targets = dict()

        for fd in self.function_call_depths:
            if fd['functionSourceFile'].replace(" ","") == "":
                continue

            if fd['functionSourceFile'] not in file_targets:
                file_targets[fd['functionSourceFile']] = set()
            file_targets[fd['functionSourceFile']].add(fd['function_name'])
        self.file_targets = file_targets


    def get_total_basic_blocks(self):
        total_basic_blocks = 0
        for func in self.funcsReachedByFuzzer:
            for fd in self.all_function_data:
                if fd['functionName'] == func:
                    total_basic_blocks += fd['BBCount']
        self.total_basic_blocks = total_basic_blocks

    def get_total_cyclomatic_complexity(self):
        self.total_cyclomatic_complexity = 0
        for func in self.funcsReachedByFuzzer:
            for fd in self.all_function_data:
                if fd['functionName'] == func:
                    self.total_cyclomatic_complexity += fd['CyclomaticComplexity']

    def accummulate_profile(self, target_folder):
        self.set_all_reached_functions()
        self.set_all_unreached_functions()
        self.correlate_runtime_coverage_with_reachability(target_folder)
        self.get_file_targets()
        self.get_total_basic_blocks()
        self.get_total_cyclomatic_complexity()



def read_fuzzer_data_file_to_profile(filename):
    if not os.path.isfile(filename) or not os.path.isfile(filename+".yaml"):
        return None

    data_dict_yaml = data_file_read_all_function_data_yaml(filename + ".yaml")
    if data_dict_yaml == None:
        return None

    # Read data about all functions
    #data_dict = dict()
    #function_call_depths = data_file_read_calltree(filename)
    #data_dict['fuzzer-information'] =  { 'functionSourceFile' : data_dict_yaml['Fuzzer filename'] }
    #data_dict['function_call_depths'] = function_call_depths
    #data_dict['all_function_data'] = data_dict_yaml['All functions']['Elements']

    profile = FuzzerProfile(filename, data_dict_yaml)

    return profile

def refine_profile(profile):
    """
    Removes BASE_DIR from source paths in a given profile. 
    """
    global BASE_DIR
    if BASE_DIR == None:
        return

    profile['fuzzer-information']['functionSourceFile'] = profile['fuzzer-information']['functionSourceFile'].replace(BASE_DIR, "")
    for node in profile['function_call_depths']:
        node['functionSourceFile'] = node['functionSourceFile'].replace(BASE_DIR, "")

    new_dict = {}
    for key in profile['file_targets']:
        new_dict[key.replace(BASE_DIR, "")] = profile['file_targets'][key]
    profile['file_targets'] = new_dict

class MergedProjectProfile:
    """
    Class for storing information about all fuzzers combined in a given project.
    """
    def __init__(self, profiles):
        self.name = None
        self.profiles = profiles


        self.all_functions = list()
        self.unreached_functions = set()
        self.functions_reached = set()

        # Populate functions reached
        for profile in profiles:
            for func_name in profile.funcsReachedByFuzzer:
                self.functions_reached.add(func_name)

        # Set all unreached functions
        for profile in profiles:
            for func_name in profile.funcsUnreachedByFuzzer:
                if func_name not in self.functions_reached:
                    self.unreached_functions.add(func_name)

        # Gather data on functions
        for profile in profiles:
            for fd in profile.all_function_data:
                if ("sanitizer" in fd['functionName'] or 
                        "llvm" in fd['functionName']):
                        #"LLVMFuzzerTestOneInput" in fd['functionName'] or 
                    continue

                # Find hit count
                hitcount = 0
                for p2 in profiles:
                    if fd['functionName'] in p2.funcsReachedByFuzzer:
                        hitcount += 1
                # Only insert if it is not a duplicate
                is_duplicate = False
                for fd1 in self.all_functions:
                    if fd1['functionName'] == fd['functionName']:
                        is_duplicate = True
                        break
                fd['hitcount'] = hitcount
                if not is_duplicate:
                    #print("T1: %s"%(str(fd['functionsReached'])))
                    self.all_functions.append(fd)


        # Identify how many times each function is reached by other functions.
        for fd1 in self.all_functions:
            incoming_references = list()
            for fd2 in self.all_functions:
                if fd1['functionName'] in fd2['functionsReached']:
                    incoming_references.append(fd2)
            fd1['incoming_references'] = incoming_references



        # Gather complexity information about each function
        for fd10 in self.all_functions:
            total_cyclomatic_complexity = 0
            for fd20 in self.all_functions:
                if fd20['functionName'] in fd10['functionsReached']:
                    total_cyclomatic_complexity += fd20['CyclomaticComplexity']

            # Check how much complexity this one will uncover.
            total_new_complexity = 0
            for fd21 in self.all_functions:
                if fd21['functionName'] in fd10['functionsReached'] and fd21['hitcount'] == 0:
                    total_new_complexity += fd21['CyclomaticComplexity']
            if fd10['hitcount'] == 0:
                fd10['new_unreached_complexity'] = total_new_complexity + (fd10['CyclomaticComplexity'])
            else:
                fd10['new_unreached_complexity'] = total_new_complexity

            fd10['total_cyclomatic_complexity'] = total_cyclomatic_complexity + fd10['CyclomaticComplexity']

        do_refinement = False
        if do_refinement:
            refine_paths(merged_profile)

    def get_total_unreached_function_count(self):
        unreached_function_count = 0
        for fd in self.all_functions:
            if fd['hitcount'] == 0:
                unreached_function_count += 1
        return unreached_function_count

    def get_total_reached_function_count(self):
        reached_function_count = 0
        for fd in self.all_functions:
            if fd['hitcount'] != 0:
                reached_function_count += 1
        return reached_function_count


def add_func_to_reached_and_clone(merged_profile_old, func_dict_old):
    merged_profile = copy.deepcopy(merged_profile_old)

    # Update the hitcount of the function in the new merged profile.
    for fd_tmp in merged_profile.all_functions:
        if fd_tmp['functionName'] == func_dict_old['functionName'] and fd_tmp['CyclomaticComplexity'] == func_dict_old['CyclomaticComplexity']:
            #print("We found the function, setting hit count %s"%(fd_tmp['functionName']))
            fd_tmp['hitcount'] = 1
        if fd_tmp['functionName'] in func_dict_old['functionsReached'] and fd_tmp['hitcount'] == 0:
            fd_tmp['hitcount'] = 1
    
    for fd10 in merged_profile.all_functions:
        total_cyclomatic_complexity = 0
        for fd20 in merged_profile.all_functions:
            if fd20['functionName'] in fd10['functionsReached']:
                total_cyclomatic_complexity += fd20['CyclomaticComplexity']

        # Check how much complexity this one will uncover.
        total_new_complexity = 0
        for fd21 in merged_profile.all_functions:
            if fd21['functionName'] in fd10['functionsReached'] and fd21['hitcount'] == 0:
                total_new_complexity += fd21['CyclomaticComplexity']
        if fd10['hitcount'] == 0:
            fd10['new_unreached_complexity'] = total_new_complexity + (fd10['CyclomaticComplexity'])
        else:
            fd10['new_unreached_complexity'] = total_new_complexity
        fd10['total_cyclomatic_complexity'] = total_cyclomatic_complexity + fd10['CyclomaticComplexity']

    return merged_profile
    

def load_all_profiles(target_folder):
    # Get the introspector profile with raw data from each fuzzer in the target folder.
    data_files = fuzz_utils.get_all_files_in_tree_with_suffix(target_folder, ".data")

    # Parse and analyse the data from each fuzzer.
    profiles = []
    print(" - found %d profiles to load"%(len(data_files)))
    for data_file in data_files:
        print(" - loading %s"%(data_file))
        # Read the .data file
        profile = read_fuzzer_data_file_to_profile(data_file)
        if profile != None:
            profiles.append(profile)
    return profiles
