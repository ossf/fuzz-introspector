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
import copy
import logging

import fuzz_cfg_load
import fuzz_cov_load
import fuzz_utils

l = logging.getLogger(name=__name__)

def normalise_str(s1):
    return s1.replace("\t", "").replace("\r", "").replace("\n", "").replace(" ", "")

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
        self.incoming_references = list()

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
        self.function_call_depths = fuzz_cfg_load.data_file_read_calltree(filename)
        self.fuzzer_source_file = data_dict_yaml['Fuzzer filename']

        # Create a list of all the functions.
        self.all_class_functions = dict()
        for elem in data_dict_yaml['All functions']['Elements']:
            func_profile = FunctionProfile(elem['functionName'])
            func_profile.migrate_from_yaml_elem(elem)
            self.all_class_functions[func_profile.function_name] = func_profile

    def refine_paths(self, basefolder):
        """
        Removes the project_profile's basefolder from source paths in a given profile. 
        """
        self.fuzzer_source_file = self.fuzzer_source_file.replace(basefolder, "")
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
        #self.functions_reached_by_fuzzer = list()
        self.functions_reached_by_fuzzer = self.all_class_functions["LLVMFuzzerTestOneInput"].functions_reached
        #for func in self.all_class_functions:
        #    if func.function_name == "LLVMFuzzerTestOneInput":
        #        self.functions_reached_by_fuzzer = func.functions_reached

    def reaches(self, func_name):
        return func_name in self.functions_reached_by_fuzzer

    def set_all_unreached_functions(self):
        """
        sets self.functions_unreached_by_fuzzer to all functiosn in self.all_class_functions
        that are not in self.functions_reached_by_fuzzer
        """
        self.functions_unreached_by_fuzzer = list()
        for func_k, func in self.all_class_functions.items():
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
    def get_function_coverage(self, function_name, should_normalise=False):
        """
        Get the tuples reflecting coverage map of a given function
        """
        if not should_normalise:
            if not function_name in self.coverage['coverage-map']:
                return []
            return self.coverage['coverage-map'][function_name]
        # should_normalise
        for funcname in self.coverage['coverage-map']:
            normalised_funcname = fuzz_utils.demangle_cpp_func(normalise_str(funcname))
            if normalised_funcname == function_name:
                return self.coverage['coverage-map'][funcname]

        # In case of errs return empty list
        return []


    def get_target_fuzzer_filename(self):
        return self.fuzzer_source_file.split("/")[-1].replace(".cpp","").replace(".c","")

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
            fd = self.all_class_functions[func]
            total_basic_blocks += fd.bb_count
        self.total_basic_blocks = total_basic_blocks

    def get_total_cyclomatic_complexity(self):
        """
        sets self.total_cyclomatic_complexity to the sum of cyclomatic complexity
        of all functions reached by this fuzzer.
        """
        self.total_cyclomatic_complexity = 0
        for func in self.functions_reached_by_fuzzer:
            fd = self.all_class_functions[func]
            self.total_cyclomatic_complexity += fd.cyclomatic_complexity

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
        self.all_functions = dict()
        self.unreached_functions = set()
        self.functions_reached = set()

        l.info("Creating merged profile of %d profiles"%(len(self.profiles)))
        # Populate functions reached
        l.info("Populating functions reached")
        for profile in profiles:
            for func_name in profile.functions_reached_by_fuzzer:
                self.functions_reached.add(func_name)

        # Set all unreached functions
        l.info("Populating functions unreached")
        for profile in profiles:
            for func_name in profile.functions_unreached_by_fuzzer:
                if func_name not in self.functions_reached:
                    self.unreached_functions.add(func_name)

        # Add all functions from the various profiles into the merged profile. Don't
        # add duplicates
        l.info("Creating all_functions dictionary")
        excluded_functions = {
                    "sanitizer", "llvm"
                }
        for profile in profiles:
            for fd_k, fd in profile.all_class_functions.items():
                exclude = len([ef for ef in excluded_functions if ef in fd.function_name]) != 0
                if exclude:
                    continue

                # Find hit count and whether it has been handled already
                hitcount = len([p for p in profiles if p.reaches(fd.function_name)])
                fd.hitcount = hitcount
                if fd.function_name not in self.all_functions:
                    self.all_functions[fd.function_name] = fd

        # Gather complexity information about each function
        l.info("Gathering complexity and incoming references of each function")
        for fd10_k, fd10 in self.all_functions.items():
            total_cyclomatic_complexity = 0
            total_new_complexity = 0
            incoming_references = list()

            for reached_func_name in fd10.functions_reached:
                fd20 = self.all_functions[reached_func_name]
                fd20.incoming_references.append(fd10.function_name)
                total_cyclomatic_complexity += fd20.cyclomatic_complexity
                if fd20.hitcount == 0:
                    total_new_complexity += fd20.cyclomatic_complexity

            if fd10.hitcount == 0:
                fd10.new_unreached_complexity = total_new_complexity + (fd10.cyclomatic_complexity)
            else:
                fd10.new_unreached_complexity = total_new_complexity
            fd10.total_cyclomatic_complexity = total_cyclomatic_complexity + fd10.cyclomatic_complexity
        l.info("Completed creationg of merged profile")

    def get_total_complexity(self):
        reached_complexity = 0
        unreached_complexity = 0
        for fd_k, fd in self.all_functions.items():
            if fd.hitcount == 0:
                unreached_complexity += fd.cyclomatic_complexity
            else:
                reached_complexity += fd.cyclomatic_complexity
        return reached_complexity, unreached_complexity

    def get_total_unreached_function_count(self):
        unreached_function_count = 0
        for fd_k, fd in self.all_functions.items():
            if fd.hitcount == 0:
                unreached_function_count += 1
        return unreached_function_count

    def get_total_reached_function_count(self):
        reached_function_count = 0
        for fd_k, fd in self.all_functions.items():
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
        for func_k, func in self.all_functions.items():
            if func.function_source_file != "/" and "/usr/include/" not in func.function_source_file:
                all_strs.append(func.function_source_file)
        return fuzz_utils.longest_common_prefix(all_strs)

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

    return FuzzerProfile(filename, data_dict_yaml)

def add_func_to_reached_and_clone(merged_profile_old, func_to_add):
    """
    This function adds new functions as "reached" in a merged profile, and returns
    a new copy of the merged profile with reachability information as if the
    functions in func_to_add are added to the merged profile. The use of this is
    to calculate what the state will be of a merged profile by targetting a new set
    of functions.

    We can use this function in a computation of "optimum fuzzer target analysis", which
    computes what the combination of ideal function targets.
    """
    l.info("Perfoming a deepcopy")
    merged_profile = copy.deepcopy(merged_profile_old)

    # Update the hitcount of the function in the new merged profile.
    l.info("Updating hitcount")
    fd_tmp = merged_profile.all_functions[func_to_add.function_name]
    if fd_tmp.cyclomatic_complexity == func_to_add.cyclomatic_complexity:
        fd_tmp.hitcount = 1
    for func_name in func_to_add.functions_reached:
        fd_tmp = merged_profile.all_functions[func_name]
        if fd_tmp.hitcount == 0:
            fd_tmp.hitcount = 1

    # Since the hitcounts has been updated in the profile, we now need to update
    # data such as total complexity covered of the fuzzer, uncovered complexity, etc.
    # Essentially, we need to re-organise all analysis that is based on hitcounts.

    # TODO: this could be improved. Essentially, instead of having these complicated loops
    # we create a new profile from scratch based on an array of functions. THis migth be easier
    # to deal with and also more modular for future work.
    l.info("Updating remaining data")
    for fd10_k, fd10 in merged_profile.all_functions.items():
        total_cyclomatic_complexity = 0
        total_new_complexity = 0

        for reached_func_name in fd10.functions_reached:
            fd20 = merged_profile.all_functions[reached_func_name]
            total_cyclomatic_complexity += fd20.cyclomatic_complexity
            if fd20.hitcount == 0:
                total_new_complexity += fd20.cyclomatic_complexity
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
    l.info(" - found %d profiles to load"%(len(data_files)))
    for data_file in data_files:
        l.info(" - loading %s"%(data_file))
        # Read the .data file
        profile = read_fuzzer_data_file_to_profile(data_file)
        if profile != None:
            profiles.append(profile)
    return profiles
