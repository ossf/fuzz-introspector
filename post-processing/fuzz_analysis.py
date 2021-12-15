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

"""Performs analysis on the profiles output from fuzz introspector LLVM pass"""
import os
import copy
import fuzz_data_loader
import cxxfilt

def analysis_get_optimal_targets(merged_profile):
    """
    Finds the top reachable functions with minimum overlap.
    Each of these functions is not be reachable by another function
    in the returned set, but, they may reach some of the same functions.
    """
    print("    - in analysis_get_optimal_targets", end=" ")
    optimal_set = set()
    target_fds = list()
    #for fd in reversed(sorted(merged_profile.all_functions, key=lambda x: len(x['functionsReached']))):
    for fd in reversed(sorted(merged_profile.all_functions, key=lambda x: len(x.functions_reached))):
        total_vals = 0
        for t in optimal_set:
            if t in fd.functions_reached:
                total_vals += 1
        
        if fd.hitcount != 0:
            continue

        if len(fd.functions_reached) < 1:
            continue

        if fd.arg_count == 0:
            continue

        # We do not care about "main2" functions
        if "main2" in fd.function_name:
            continue

        if fd.total_cyclomatic_complexity < 20:
            continue

        # Ensure that the overlap with existing functions in our optimal set is not excessive
        # set is not excessive. There is likely some overlap because of use of
        # utility functions and similar.
        #proportion = (total_vals*1.0)/(len(fd['functionsReached'])*1.0)

        #if proportion == 1.0:
        #    continue

        condition1 = True #proportion < 0.5

        # We also want to include all targets that have a fairly high complexity.
        condition2 = fd.bb_count > 1

        if not (condition1 or condition2):
            continue

        for func_name in fd.functions_reached:
            optimal_set.add(func_name)

        target_fds.append(fd)
    print(". Done")
    #optimal_set = set()
    #for fd in merged_profile['all_function_data']
    return target_fds, optimal_set


def analysis_synthesize_simple_targets(merged_profile):
    '''
    Function for synthesizing fuzz targets. The way this one works is by finding
    optimal targets that don't overlap too much with each other. The fuzz targets
    are created to target functions in specific files, so all functions targeted 
    in each fuzzer will be from the same source file.

    In a sense, this is more of a PoC wy to do some analysis on the data we have.
    It is likely that we could do something much better.
    '''
    print("  - in analysis_synthesize_simple_targets")
    new_merged_profile = copy.deepcopy(merged_profile)
    target_fds, optimal_set = analysis_get_optimal_targets(merged_profile)
    fuzzer_code = "#include \"ada_fuzz_header.h\"\n"
    fuzzer_code += "\n"
    fuzzer_code += "int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n"
    fuzzer_code += "  af_safe_gb_init(data, size);\n\n"
    variables_to_create = []

    target_codes = dict()
    optimal_functions_targeted = []

    var_idx = 0
    func_count = len(merged_profile.all_functions)
    if func_count > 20000:
        max_count = 1
    elif func_count > 10000 and func_count < 20000:
        max_count = 5
    elif func_count > 2000 and func_count < 10000:
        max_count = 7
    else:
        max_count = 10
    #max_count = 8
    curr_count = 0
    while curr_count < max_count:
        print("  - sorting by unreached complexity. ", end="")
        sorted_by_undiscovered_complexity = list(reversed(sorted(target_fds, key=lambda x: int(x['new_unreached_complexity']))))
        print(". Done")

        #if len(sorted_by_undiscovered_complexity) == 0:
        #    break
        #tfd = sorted_by_undiscovered_complexity[0]
        #if tfd == None:
        #    break

        try:
            tfd = sorted_by_undiscovered_complexity[0]
        except:
            break
        if tfd == None:
            break

        #to_continue = True
        #if tfd['new_unreached_complexity'] <= 35:
        #    to_continue = False
        #if curr_count >= max_count:
        #    to_continue = False
        #if not to_continue:
        #    break
        if tfd['new_unreached_complexity'] <= 35:
            break
        #if to_continue:
        curr_count += 1

        optimal_functions_targeted.append(tfd)

        code = ""
        code_var_decl = ""
        variable_creation = ""
        var_order = []
        for arg_type in tfd['argTypes']:
            arg_type = arg_type.replace(" ","")
            if arg_type == "char**":
                code_var_decl += "  char **new_var%d = af_get_double_char_p();\n"%(var_idx)
                # We dont want the below line but instead we want to ensure 
                # we always return something valid.
                var_order.append("new_var%d"%(var_idx))
                var_idx += 1
            elif arg_type == "char*":
                code_var_decl += "  char *new_var%d = ada_safe_get_char_p();\n"%(var_idx)
                var_order.append("new_var%d"%(var_idx))
                var_idx += 1
            elif arg_type == "int":
                code_var_decl += "  int new_var%d = ada_safe_get_int();\n"%(var_idx)
                var_order.append("new_var%d"%(var_idx))
                var_idx += 1
            elif arg_type == "int*":
                code_var_decl += "  int *new_var%d = af_get_int_p();\n"%(var_idx)
                var_order.append("new_var%d"%(var_idx))
                var_idx += 1
            elif "struct" in arg_type and "*" in arg_type and "**" not in arg_type:
                code_var_decl += "  %s new_var%d = calloc(sizeof(%s), 1);\n"%(arg_type.replace(".", " "), var_idx, arg_type.replace(".", " ").replace("*",""))
                var_order.append("new_var%d"%(var_idx))
                var_idx += 1
            else:
                code_var_decl += "  UNKNOWN_TYPE unknown_%d;\n"%(var_idx)
                var_order.append("unknown_%d"%(var_idx))
                var_idx += 1
        #if len(var_order) > 0:

        # Now add the function call. 
        code += "  /* target %s */\n"%(tfd['functionName'])
        #code += "  /* linkage %s */\n"%(tfd['linkageType'])
        code += code_var_decl
        code += "  %s("%(tfd['functionName'])
        for idx in range(len(var_order)):
            code += var_order[idx]
            if idx < (len(var_order)-1):
                code += ", "
        code += ");\n"
        code += "\n"
        if tfd['functionSourceFile'] not in target_codes:
            target_codes[tfd['functionSourceFile']] = dict()
            target_codes[tfd['functionSourceFile']]['source_code'] = ""
            target_codes[tfd['functionSourceFile']]['target_fds'] = list()

        #print("[Fuzz synthesizer] Function %s - adding code: %s"%(tfd['functionName'], code))
        target_codes[tfd['functionSourceFile']]['source_code'] += code
        target_codes[tfd['functionSourceFile']]['target_fds'].append(tfd)


        print("  - calling add_func_t_reached_and_clone. ", end="")
        new_merged_profile = fuzz_data_loader.add_func_to_reached_and_clone(new_merged_profile, tfd)
        print(". Done")
        for tmp_ff in new_merged_profile.all_functions:
            if tmp_ff['functionName'] == tfd['functionName'] and tmp_ff['hitcount'] == 0:
                print("Error. Hitcount did not get set for some reason")
                exit(0)

        # We need to update the optimal targets here.
        # We only need to do this operation if we are actually going to continue analysis

        if curr_count < max_count:
            target_fds, optimal_set = analysis_get_optimal_targets(new_merged_profile)

    final_fuzzers = dict()

    #print("Fuzzers:")
    for filename in target_codes:
        file_fuzzer_code = fuzzer_code
        #file_fuzzer_code += "\n"
        file_fuzzer_code += target_codes[filename]['source_code']
        file_fuzzer_code += "  af_safe_gb_cleanup();\n"
        file_fuzzer_code += "}\n"
        #print("Fuzzer for %s:"%(filename))
        #print("%s"%(file_fuzzer_code))
        #print("-"*75)

        final_fuzzers[filename] = dict()
        final_fuzzers[filename]['source_code'] = file_fuzzer_code
        final_fuzzers[filename]['target_fds'] = target_codes[filename]['target_fds']


    #fuzzer_code += "  af_gb_cleanup();\n"
    #fuzzer_code += "\n}\n"
    #print("Fuzzer code:")
    #print(fuzzer_code)
    #print("-----------------")

    #print("Optimal target functions")
    #for nfd in optimal_functions_targeted:
    #    print("%s"%(nfd['functionName']))
    #print("<"*45)
    return final_fuzzers, new_merged_profile, optimal_functions_targeted

def analysis_get_targets_for_existing_fuzzers(profiles, merged_profile):
    targets_for_existing_fuzzers = []
    # Find promising targets for each fuzzer based on which 
    # files it already targets.
    for fd in merged_profile['all_function_data']:
        if fd['hitcount'] != 0:
            continue

        if fd['total_cyclomatic_complexity'] <= 40:
            continue

        # Find the best profile
        best_profile = None
        best_proportion = 0.0
        for profile in profiles:
            if fd['functionSourceFile'].replace(" ","") not in profile['file_targets']:
                # The file of the function is hit by the fuzzer. 
                # In this case we are not interested.
                continue

            total_targets = 0
            for file_target in profile['file_targets']:
                total_targets += len(profile['file_targets'][file_target])

            function_file_targets = len(profile['file_targets'][fd['functionSourceFile'].replace(" ","")])

            proportion = (function_file_targets*1.0) / (total_targets*1.0)
            # In order to ensure focus, we want to have the fuzzer at least dedicate 8% of 
            # its work to this file.
            if proportion <= 0.1:
                continue

            if proportion > best_proportion or best_profile == None:
                best_proportion = proportion
                best_profile = profile

        if best_profile != None:
            targets_for_existing_fuzzers.append((fd, best_profile, best_proportion))

    return targets_for_existing_fuzzers      
