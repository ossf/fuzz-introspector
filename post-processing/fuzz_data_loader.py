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
        self.function_source_file = None
        self.linkage_type = None
        self.function_linenumber = None
        self.return_type = None
        self.arg_count = None
        self.arg_types = None
        self.arg_names = None
        self.bb_count = None
        self.i_count = None
        self.edge_count = None
        self.cyclomatic_complexity = None
        self.functions_reached = None
        self.function_uses = None
        self.function_depth = None

    def migrate_from_yaml_elem(self, elem):
        self.function_name = elem['functionName']
        self.function_source_file = elem['functionSourceFile']
        self.linkage_type = elem['linkageType']
        self.function_linenumber = elem['functionLinenumber']
        self.return_type = elem['returnType']
        self.arg_count = elem['argCount']
        self.arg_types = elem['argTypes']
        self.arg_names = elem['argNames']
        self.bb_count = elem['BBCount']
        self.i_count = elem['ICount']
        self.edge_count = elem['EdgeCount']
        self.cyclomatic_complexity = elem['CyclomaticComplexity']
        self.functions_reached = elem['functionsReached']
        self.function_uses = elem['functionUses']
        self.function_depth = elem['functionDepth']

class FuzzerProfile:
    """
    Class for storing information about a given Fuzzer.

    This class essentially holds data corresponding to the output of run of the LLVM
    plugin. That means, the output from the plugin for a single fuzzer.
    """
    def __init__(self, filename, data_dict_yaml):
        self.fuzzer_information = dict()

        # Read data about all functions
        self.function_call_depths = fuzz_cfg_load.data_file_read_calltree(filename)
        self.fuzzer_information =  { 'functionSourceFile' : data_dict_yaml['Fuzzer filename'] }

        # Create a list of all the functions.
        self.all_class_functions = list()
        for elem in data_dict_yaml['All functions']['Elements']:
            func_profile = FunctionProfile(elem['functionName'])
            func_profile.migrate_from_yaml_elem(elem)
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
        """
        sets self.functions_reached_by_fuzzer to all functions reached by LLVMFuzzerTestOneInput
        """
        self.functions_reached_by_fuzzer = list()
        for func in self.all_class_functions:
            if func.function_name == "LLVMFuzzerTestOneInput":
                self.functions_reached_by_fuzzer = func.functions_reached

    def set_all_unreached_functions(self):
        """
        sets self.functions_unreached_by_fuzzer to all functiosn in self.all_class_functions
        that are not in self.functions_reached_by_fuzzer
        """
        self.functions_unreached_by_fuzzer = list()
        for func in self.all_class_functions:
            in_fuzzer = False
            for func2_name in self.functions_reached_by_fuzzer:
                if func2_name == func.function_name:
                    in_fuzzer = True
            if not in_fuzzer:
                self.functions_unreached_by_fuzzer.append(func.function_name)

    def load_coverage(self, target_folder):
        # Merge any runtime coverage data that we may have to correlate
        # reachability and runtime coverage information.
        functions_hit, coverage_map = fuzz_cov_load.llvm_cov_load(target_folder, self.get_target_fuzzer_filename())
        self.coverage = {
                'functions-hit' : functions_hit,
                'coverage-map' : coverage_map
                }

    def get_target_fuzzer_filename(self):
        return self.fuzzer_information['functionSourceFile'].split("/")[-1].replace(".cpp","").replace(".c","")

    def get_file_targets(self):
        """
        Sets self.file_targets to be a dictionarty of string to string.
        Each key in the dictionary is a filename and the corresponding value is
        a set of strings containing strings which are the names of the functions
        in the given file that are reached by the fuzzer.
        """
        filenames = set()
        self.file_targets = dict()
        for fd in self.function_call_depths:
            if fd['functionSourceFile'].replace(" ","") == "":
                continue
            if fd['functionSourceFile'] not in self.file_targets:
                self.file_targets[fd['functionSourceFile']] = set()
            self.file_targets[fd['functionSourceFile']].add(fd['function_name'])

    def get_total_basic_blocks(self):
        """
        sets self.total_basic_blocks to the sym of basic blocks of all the functions
        reached by this fuzzer.
        """
        total_basic_blocks = 0
        for func in self.functions_reached_by_fuzzer:
            for fd in self.all_class_functions:
                if fd.function_name == func:
                    total_basic_blocks += fd.bb_count
                    break
        self.total_basic_blocks = total_basic_blocks

    def get_total_cyclomatic_complexity(self):
        """
        sets self.total_cyclomatic_complexity to the sum of cyclomatic complexity
        of all functions reached by this fuzzer.
        """
        self.total_cyclomatic_complexity = 0
        for func in self.functions_reached_by_fuzzer:
            for fd in self.all_class_functions:
                if fd.function_name == func:
                    self.total_cyclomatic_complexity += fd.cyclomatic_complexity
                    break

    def accummulate_profile(self, target_folder):
        """
        Triggers various analyses on the data of the fuzzer. This is used after a
        profile has been initialised to generate more interesting data.
        """
        self.set_all_reached_functions()
        self.set_all_unreached_functions()
        self.load_coverage(target_folder)
        self.get_file_targets()
        self.get_total_basic_blocks()
        self.get_total_cyclomatic_complexity()


class MergedProjectProfile:
    """
    Class for storing information about all fuzzers combined in a given project.

    This means, it contains data for all fuzzers in a given project, and digests
    the manner in a way that makes sense from a project-scope perspective. For
    example, it does project-wide analysis of reachable/unreachable functions by
    digesting data from all the fuzzers in the project.
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

        # Add all functions from the various profiles into the merged profile. Don't
        # add duplicates
        excluded_functions = {
                    "sanitizer", "llvm"
                }
        for profile in profiles:
            for fd in profile.all_class_functions:
                exclude = len([ef for ef in excluded_functions if ef in fd.function_name]) != 0
                if exclude:
                    continue

                # Find hit count
                hitcount = 0
                for p2 in profiles:
                    if fd.function_name in p2.functions_reached_by_fuzzer:
                        hitcount += 1
                # Only insert if it is not a duplicate
                is_duplicate = False
                for fd1 in self.all_functions:
                    if fd1.function_name == fd.function_name:
                        is_duplicate = True
                        break
                fd.hitcount = hitcount
                if not is_duplicate:
                    self.all_functions.append(fd)


        # Identify how many times each function is reached by other functions.
        for fd1 in self.all_functions:
            incoming_references = list()
            for fd2 in self.all_functions:
                if fd1.function_name in fd2.functions_reached:
                    incoming_references.append(fd2)
            fd1.incoming_references = incoming_references

        # Gather complexity information about each function
        for fd10 in self.all_functions:
            total_cyclomatic_complexity = 0
            for fd20 in self.all_functions:
                if fd20.function_name in fd10.functions_reached:
                    total_cyclomatic_complexity += fd20.cyclomatic_complexity

            # Check how much complexity this one will uncover.
            total_new_complexity = 0
            for fd21 in self.all_functions:
                if fd21.function_name in fd10.functions_reached and fd21.hitcount == 0:
                    total_new_complexity += fd21.cyclomatic_complexity
            if fd10.hitcount == 0:
                fd10.new_unreached_complexity = total_new_complexity + (fd10.cyclomatic_complexity)
            else:
                fd10.new_unreached_complexity = total_new_complexity
            fd10.total_cyclomatic_complexity = total_cyclomatic_complexity + fd10.cyclomatic_complexity

    def get_total_unreached_function_count(self):
        unreached_function_count = 0
        for fd in self.all_functions:
            if fd.hitcount == 0:
                unreached_function_count += 1
        return unreached_function_count

    def get_total_reached_function_count(self):
        reached_function_count = 0
        for fd in self.all_functions:
            if fd.hitcount != 0:
                reached_function_count += 1
        return reached_function_count

    def get_basefolder(self):
        """
        Identifies a common path-prefix amongst source files in 
        This is used to remove locations within a host system to 
        essentially make paths as if they were from the root of the source code project.
        """
        all_strs = []
        for func in self.all_functions:
            #if func['functionSourceFile'] != "/" and "/usr/include/" not in func['functionSourceFile']:
            if func.function_source_file != "/" and "/usr/include/" not in func.function_source_file:
                all_strs.append(func.function_source_file)
        base = fuzz_utils.longest_common_prefix(all_strs)
        return base

def read_fuzzer_data_file_to_profile(filename):
    """
    For a given .data file (CFG) read the corresponding .yaml file
    This is a bit odd way of doing it and should probably be improved.
    """
    if not os.path.isfile(filename) or not os.path.isfile(filename+".yaml"):
        return None

    data_dict_yaml = fuzz_utils.data_file_read_yaml(filename + ".yaml")
    if data_dict_yaml == None:
        return None

    profile = FuzzerProfile(filename, data_dict_yaml)
    return profile


def add_func_to_reached_and_clone(merged_profile_old, func_dict_old):
    merged_profile = copy.deepcopy(merged_profile_old)

    # Update the hitcount of the function in the new merged profile.
    for fd_tmp in merged_profile.all_functions:
        if fd_tmp.function_name == func_dict_old.function_name and fd_tmp.cyclomatic_complexity == func_dict_old.cyclomatic_complexity:
            #print("We found the function, setting hit count %s"%(fd_tmp['functionName']))
            fd_tmp.hitcount = 1
        if fd_tmp.function_name in func_dict_old.functions_reached and fd_tmp.hitcount == 0:
            fd_tmp.hitcount = 1
    
    for fd10 in merged_profile.all_functions:
        total_cyclomatic_complexity = 0
        for fd20 in merged_profile.all_functions:
            if fd20.function_name in fd10.functions_reached:
                total_cyclomatic_complexity += fd20.cyclomatic_complexity

        # Check how much complexity this one will uncover.
        total_new_complexity = 0
        for fd21 in merged_profile.all_functions:
            if fd21.function_name in fd10.functions_reached and fd21.hitcount == 0:
                total_new_complexity += fd21.cyclomatic_complexity
        if fd10.hitcount == 0:
            fd10.new_unreached_complexity = total_new_complexity + (fd10.cyclomatic_complexity)
        else:
            fd10.new_unreached_complexity = total_new_complexity
        fd10.total_cyclomatic_complexity = total_cyclomatic_complexity + fd10.cyclomatic_complexity

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
