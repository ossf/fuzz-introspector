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
import fuzz_cfg_load
import fuzz_cov_load
import fuzz_html
import fuzz_utils

class FunctionProfile:
    """
    Class for storing information about a given Function
    """

    def __init__(self, function_name):
        self.function_name = function_name


class FuzzerProfile:
    """
    Class for storing information about a given Fuzzer
    """
    def __init__(self, filename, data_dict_yaml):
        self.fuzzer_information = dict()

        # Read data about all functions
        data_dict = dict()
        self.function_call_depths = fuzz_cfg_load.data_file_read_calltree(filename)
        self.fuzzer_information =  { 'functionSourceFile' : data_dict_yaml['Fuzzer filename'] }
        self.all_function_data = data_dict_yaml['All functions']['Elements']

        self.all_class_functions = list()
        for elem in self.all_function_data:
            func_profile = FunctionProfile(elem['functionName'])
            func_profile.function_name = elem['functionName']
            func_profile.function_source_file = elem['functionSourceFile']
            func_profile.linkage_type = elem['linkageType']
            func_profile.function_linenumber = elem['functionLinenumber']
            func_profile.return_type = elem['returnType']
            func_profile.arg_count = elem['argCount']
            func_profile.arg_types = elem['argTypes']
            func_profile.arg_names = elem['argNames']
            func_profile.bb_count = elem['BBCount']
            func_profile.i_count = elem['ICount']
            func_profile.edge_count = elem['EdgeCount']
            func_profile.cyclomatic_complexity = elem['CyclomaticComplexity']
            func_profile.functions_reached = elem['functionsReached']
            func_profile.function_uses = elem['functionUses']

            self.all_class_functions.append(func_profile)

    def refine_paths(self, basefolder):
        """
        Removes the project_profile's basefolder from source paths in a given profile. 
        """
        self.fuzzer_information['functionSourceFile'] = self.fuzzer_information['functionSourceFile'].replace(basefolder, "")
        for node in self.function_call_depths:
            node['functionSourceFile'] = node['functionSourceFile'].replace(basefolder, "")

        new_dict = {}
        for key in self.file_targets:
            new_dict[key.replace(basefolder, "")] = self.file_targets[key]
        self.file_targets = new_dict

    def set_all_reached_functions(self):
        self.functions_reached_by_fuzzer = list()
        for func in self.all_class_functions:
            if func.function_name == "LLVMFuzzerTestOneInput":
                self.functions_reached_by_fuzzer = func.functions_reached

    def set_all_unreached_functions(self):
        self.functions_unreached_by_fuzzer = list()
        for func in self.all_class_functions:
            in_fuzzer = False
            for func2_name in self.functions_reached_by_fuzzer:
                if func2_name == func.function_name:
                    in_fuzzer = True
            if not in_fuzzer:
                self.functions_unreached_by_fuzzer.append(func.function_name)



    def correlate_runtime_coverage_with_reachability(self, target_folder):
        # Merge any runtime coverage data that we may have to correlate
        # reachability and runtime coverage information.
        #print("Finding coverage")
        tname = self.fuzzer_information['functionSourceFile'].split("/")[-1].replace(".cpp","").replace(".c","")
        functions_hit, coverage_map = fuzz_cov_load.llvm_cov_load(target_folder, tname)
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
        for func in self.functions_reached_by_fuzzer:
            for fd in self.all_function_data:
                if fd['functionName'] == func:
                    total_basic_blocks += fd['BBCount']
        self.total_basic_blocks = total_basic_blocks

    def get_total_cyclomatic_complexity(self):
        self.total_cyclomatic_complexity = 0
        for func in self.functions_reached_by_fuzzer:
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
            for func_name in profile.functions_reached_by_fuzzer:
                self.functions_reached.add(func_name)

        # Set all unreached functions
        for profile in profiles:
            for func_name in profile.functions_unreached_by_fuzzer:
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
                    if fd['functionName'] in p2.functions_reached_by_fuzzer:
                        hitcount += 1
                # Only insert if it is not a duplicate
                is_duplicate = False
                for fd1 in self.all_functions:
                    if fd1['functionName'] == fd['functionName']:
                        is_duplicate = True
                        break
                fd['hitcount'] = hitcount
                if not is_duplicate:
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

    def get_basefolder(self):
        """
        Identifies a common path-prefix amongst source files in all_function_data
        dictionary. This is used to remove locations within a host system to 
        essentially make paths as if they were from the root of the source code project.
        """
        all_strs = []
        for func in self.all_functions:
            if func['functionSourceFile'] != "/" and "/usr/include/" not in func['functionSourceFile']:
                all_strs.append(func['functionSourceFile'])
        base = fuzz_utils.longest_common_prefix(all_strs)
        return base

def read_fuzzer_data_file_to_profile(filename):
    """
    For a given .data file (CFG) read the corresponding .yaml file
    This is a bit odd way of doing it and should probably be improved.
    """
    if not os.path.isfile(filename) or not os.path.isfile(filename+".yaml"):
        return None

    data_dict_yaml = fuzz_utils.data_file_read_all_function_data_yaml(filename + ".yaml")
    if data_dict_yaml == None:
        return None

    profile = FuzzerProfile(filename, data_dict_yaml)
    return profile


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
