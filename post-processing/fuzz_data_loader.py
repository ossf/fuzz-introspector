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

debug = False

BASE_DIR = None

def data_file_read_all_function_data_yaml(filename):
    with open(filename, 'r') as stream:
        try:
            data_dict = yaml.safe_load(stream)
            return data_dict
        except yaml.YAMLError as exc:
            #print(exc) 
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


def identify_base_folder(merged_profile):
    all_strs = []

    for func in merged_profile['all_function_data']:#function_dict['All functions']['Elements']:
        if func['functionSourceFile'] != "/":
            #print("Function: %s"%(func['functionSourceFile']))
            all_strs.append(func['functionSourceFile'])
    
    base = longestCommonPrefix(all_strs)
    return base


def refine_paths(merged_profile):
    global BASE_DIR
    # Find the root of the files to not add unnesecary stuff.
    base = identify_base_folder(merged_profile)

    BASE_DIR = base
    #print("Base: %s"%(base))
    
    # Now clear up all source file paths
    #for func in function_dict['All functions']['Elements']:
    for func in merged_profile['all_function_data']:
        if func['functionSourceFile'] != "/":
            func['functionSourceFile'] = func['functionSourceFile'].replace(base, "")



def read_fuzzer_data_files(filename):
    if not os.path.isfile(filename):
        return None

    if not os.path.isfile(filename+".yaml"):
        return None

    data_dict_yaml = data_file_read_all_function_data_yaml(filename + ".yaml")
    if data_dict_yaml == None:
        return None


    # Read data about all functions
    data_dict = dict()
    function_call_depths = data_file_read_calltree(filename)
    data_dict['fuzzer-information'] =  { 'functionSourceFile' : data_dict_yaml['Fuzzer filename'] }
    data_dict['function_call_depths'] = function_call_depths
    data_dict['all_function_data'] = data_dict_yaml['All functions']['Elements']

    return data_dict

def refine_profile(profile):
    global BASE_DIR
    if BASE_DIR != None:
        #print("Refining: %s"%(profile['fuzzer-information']['functionSourceFile']))
        profile['fuzzer-information']['functionSourceFile'] = profile['fuzzer-information']['functionSourceFile'].replace(BASE_DIR, "")
        #print("Completed: %s"%(profile['fuzzer-information']['functionSourceFile']))


        for node in profile['function_call_depths']:
            node['functionSourceFile'] = node['functionSourceFile'].replace(BASE_DIR, "")

        new_dict = {}
        for key in profile['file_targets']:
            new_dict[key.replace(BASE_DIR, "")] = profile['file_targets'][key]
        profile['file_targets'] = new_dict
    #else:
    #    print("Am not refining")


def create_project_profile(profiles):
    """
    Merges a set of profiles into one big profile.
    We only merge a subset of the fields in each profile. Read
    the code to find out which as this changes often.
    """

    merged_profile = dict()
    merged_profile["fuzzer-information"] = set()
    merged_profile["functions-reached-by-fuzzer"] = set()
    merged_profile["unreached-functions"] = set()
    merged_profile['all_function_data'] = list()

    # first find all functions reached by all fuzzers
    for profile in profiles:
        for fname in profile['functions-reached-by-fuzzer']:
            merged_profile['functions-reached-by-fuzzer'].add(fname)

    # Now go through all unreached functions
    for profile in profiles:
        for fname in profile['unreached-functions']:
            if fname not in merged_profile['functions-reached-by-fuzzer']:
                merged_profile['unreached-functions'].add(fname)

    # Merge all of the function data. We must ensure for each function that
    # the given function is still part of the unreached functions.
    # Include a "hitcount" in the dictionary.
    for profile in profiles:
        for fd in profile['all_function_data']:
            if ("sanitizer" in fd['functionName'] or 
                    "llvm" in fd['functionName']):
                    #"LLVMFuzzerTestOneInput" in fd['functionName'] or 
                continue

            is_duplicate = False

            # Find hit count
            hitcount = 0
            for p2 in profiles:
                if fd['functionName'] in p2['functions-reached-by-fuzzer']:
                    hitcount += 1
            # Only insert if it is not a duplicate
            for fd1 in merged_profile["all_function_data"]:
                if fd1['functionName'] == fd['functionName']:
                    is_duplicate = True
                    break
            fd['hitcount'] = hitcount
            if not is_duplicate:
                #print("T1: %s"%(str(fd['functionsReached'])))
                merged_profile["all_function_data"].append(fd)

    # Identify how many times each function is reached by other functions.
    for fd1 in merged_profile['all_function_data']:
        incoming_references = list()
        for fd2 in merged_profile['all_function_data']:
            if fd1['functionName'] in fd2['functionsReached']:
                incoming_references.append(fd2)
        fd1['incoming_references'] = incoming_references

    for fd10 in merged_profile['all_function_data']:
        total_cyclomatic_complexity = 0
        for fd20 in merged_profile['all_function_data']:
            if fd20['functionName'] in fd10['functionsReached']:
                total_cyclomatic_complexity += fd20['CyclomaticComplexity']

        # Check how much complexity this one will uncover.
        total_new_complexity = 0
        for fd21 in merged_profile['all_function_data']:
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

    return merged_profile

def add_func_to_reached_and_clone(merged_profile_old, func_dict_old):
    merged_profile = copy.deepcopy(merged_profile_old)

    # Update the hitcount of the function in the new merged profile.
    for fd_tmp in merged_profile['all_function_data']:
        if fd_tmp['functionName'] == func_dict_old['functionName'] and fd_tmp['CyclomaticComplexity'] == func_dict_old['CyclomaticComplexity']:
            #print("We found the function, setting hit count %s"%(fd_tmp['functionName']))
            fd_tmp['hitcount'] = 1
        if fd_tmp['functionName'] in func_dict_old['functionsReached'] and fd_tmp['hitcount'] == 0:
            fd_tmp['hitcount'] = 1
    
    for fd10 in merged_profile['all_function_data']:
        #print("Going through function: %s"%(str(fd10)))
        #print("Length of all function data: %d"%(len(merged_profile['all_function_data'])))
        total_cyclomatic_complexity = 0
        for fd20 in merged_profile['all_function_data']:
            if fd20['functionName'] in fd10['functionsReached']:
                total_cyclomatic_complexity += fd20['CyclomaticComplexity']

        # Check how much complexity this one will uncover.
        total_new_complexity = 0
        for fd21 in merged_profile['all_function_data']:
            if fd21['functionName'] in fd10['functionsReached'] and fd21['hitcount'] == 0:
                total_new_complexity += fd21['CyclomaticComplexity']
        if fd10['hitcount'] == 0:
            fd10['new_unreached_complexity'] = total_new_complexity + (fd10['CyclomaticComplexity'])
        else:
            fd10['new_unreached_complexity'] = total_new_complexity
        fd10['total_cyclomatic_complexity'] = total_cyclomatic_complexity + fd10['CyclomaticComplexity']

    return merged_profile
    

def get_total_basic_blocks(profile):
    total_basic_blocks = 0
    for func in profile['functions-reached-by-fuzzer']:
        for fd in profile['all_function_data']:
            if fd['functionName'] == func:
                total_basic_blocks += fd['BBCount']
    return total_basic_blocks


def get_total_cyclomatic_complexity(profile):
    total_cyclomatic_complexity = 0
    for func in profile['functions-reached-by-fuzzer']:
        for fd in profile['all_function_data']:
            if fd['functionName'] == func:
                total_cyclomatic_complexity += fd['CyclomaticComplexity']
    return total_cyclomatic_complexity


def get_file_targets(profile):
    fcl = profile['function_call_depths']
    filenames = set()
    file_targets = dict()

    for fd in fcl:
        if fd['functionSourceFile'].replace(" ","") == "":
            continue

        if fd['functionSourceFile'] not in file_targets:
            file_targets[fd['functionSourceFile']] = set()
        file_targets[fd['functionSourceFile']].add(fd['function_name'])

    return file_targets
     

def get_all_profile_files(basedir, suffix):
    #print("Finding all targets")
    data_files = []
    for root, dirs, files in os.walk(basedir):
        #print("files: %s"%(str(files)))
        for f in files:
            if f.endswith(suffix):
                #print(os.path.join(root, f))
                data_files.append(os.path.join(root, f))
    return data_files


def demangle_cpp_func(funcname):
    try:
        demangled = cxxfilt.demangle(funcname.replace(" ",""))
        return demangled
    except:
        return funcname


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
    coverage_reports = get_all_profile_files(target_dir, ".covreport")
    functions_hit = set()
    coverage_map = dict()

    # Check if there is a meaningful profile and if not, we need to use all.
    found_name = False
    for pf in coverage_reports:
        if target_name != None:
            if target_name in pf:
                found_name = True

    for profile_file in coverage_reports:
        # If only coverage from a specific report should be used then filter
        # here. Otherwise, include coverage from everybody.
        if found_name:
            if target_name != None:
                if target_name not in profile_file:
                    continue

        with open(profile_file, "r") as pf:
            curr_func = None
            for line in pf:
                if len(line.replace("\n","")) > 0 and line.replace("\n","")[-1] == ":" and "|" not in line:
                    #print("We got a function definition: %s"%(line.replace("n","")))

                    if len(line.split(":")) == 3:
                        curr_func = line.replace("\n","").split(":")[1].replace(" ","").replace(":","")
                    else:
                        curr_func = line.replace("\n","").replace(" ","").replace(":","")

                    coverage_map[curr_func] = list()
                if curr_func != None and "|" in line:
                    #print("Function: %s has line: %s --- %s"%(curr_func, line.replace("\n",""), str(line.split("|"))))
                    line_number = int(line.split("|")[0])
                    try:
                        hit_times = int(line.split("|")[1].replace("k","00").replace(".",""))
                    except:
                        hit_times = 0
                    coverage_map[curr_func].append((line_number, hit_times))
                    #print("\tLine %d - hit times: %d"%(line_number, hit_times))


                # We should now normalise the potential function name
                fname = str(line.replace("\n", ""))
                if ".c" in fname and ".cpp" not in fname:
                    fname = fname.split(".c")[-1].replace(":","")
                if ".cpp" in fname:
                    fname = fname.split(".cpp")[-1].replace(":","")
                    fname = demangle_cpp_func(fname)

                if line.replace("\n","").endswith(":"):
                    fname = fname.replace(":", "")
                    fname = demangle_cpp_func(fname)
                    functions_hit.add(fname)


    #for fh in functions_hit:
    #    print("Function: %s"%(fh))

    return functions_hit, coverage_map


def correlate_runtime_coverage_with_reachability(profile, target_folder):
    # Merge any runtime coverage data that we may have to correlate
    # reachability and runtime coverage information.
    #print("Finding coverage")
    tname = profile['fuzzer-information']['functionSourceFile'].split("/")[-1].replace(".cpp","").replace(".c","")
    functions_hit, coverage_map = extract_functions_covered(target_folder, tname)
    if tname != None:
        profile['coverage'] = dict()
        profile['coverage']['functions-hit'] = functions_hit
        profile['coverage']['coverage-map'] = coverage_map
    return {'functions-hit': functions_hit ,
            'coverage-map' : coverage_map }


def find_all_reached_functions(profile):
    funcsReachedByFuzzer = list()
    for func in profile['all_function_data']:
        if func["functionName"] == "LLVMFuzzerTestOneInput":
            funcsReachedByFuzzer = func['functionsReached']
    return funcsReachedByFuzzer

def find_all_unreached_functions(profile):
    funcsUnreachedByFuzzer = list()
    for func in profile['all_function_data']:
        in_fuzzer = False
        for func_name2 in profile['functions-reached-by-fuzzer']:
            if func_name2 == func['functionName']:
                in_fuzzer = True
        if not in_fuzzer:
            funcsUnreachedByFuzzer.append(func['functionName'])
    return funcsUnreachedByFuzzer

def load_all_profiles(target_folder):
    # Get the introspector profile with raw data from each fuzzer in the target folder.
    data_files = get_all_profile_files(target_folder, ".data")

    # Parse and analyse the data from each fuzzer.
    profiles = []
    print(" - found %d profiles to load"%(len(data_files)))
    for data_file in data_files:
        print(" - loading %s"%(data_file))
        # Read the .data file
        profile = read_fuzzer_data_files(data_file)
        if profile != None:
            profiles.append(profile)
    return profiles


def accummulate_profile(profile, target_folder):
    #print("Accumulating profile")
    profile['functions-reached-by-fuzzer'] = find_all_reached_functions(profile)
    profile['unreached-functions'] = find_all_unreached_functions(profile)
    profile['coverage'] = correlate_runtime_coverage_with_reachability(profile, target_folder)
    profile['file_targets'] = get_file_targets(profile)
    profile['total-basic-block-count'] = get_total_basic_blocks(profile)
    profile['total-cyclomatic-complexity'] = get_total_cyclomatic_complexity(profile)

