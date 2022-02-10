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
import cxxfilt
import logging

from typing import (
    Any,
    Dict,
    List,
    Set,
    Tuple,
)

import fuzz_utils
import fuzz_data_loader

l = logging.getLogger(name=__name__)

def overlay_calltree_with_coverage(
        profile: fuzz_data_loader.FuzzerProfile,
        project_profile: fuzz_data_loader.MergedProjectProfile,
        coverage_url: str,
        git_repo_url: str,
        basefolder: str,
        image_name: str) -> None:
    # We use the callstack to keep track of all function parents. We need this
    # when looking up if a callsite was hit or not. This is because the coverage
    # information about a callsite is located in coverage data of the function
    # in which the callsite is placed.
    callstack = dict()
    def callstack_get_parent(n, c):
        return c[int(n['depth'])-1]

    def callstack_has_parent(n, c):
        return int(n['depth'])-1 in c

    def callstack_set_curr_node(n, name, c):
        c[int(node['depth'])] = name

    is_first = True
    ct_idx = 0
    for node in profile.function_call_depths:
        node['cov-ct-idx'] = ct_idx
        ct_idx += 1

        demangled_name = fuzz_utils.demangle_cpp_func(node['function_name'])

        # Add to callstack
        callstack_set_curr_node(node, demangled_name, callstack)

        # Get hitcount for this node
        node_hitcount = 0
        if is_first:
            # The first node is always the entry of LLVMFuzzerTestOneInput
            # LLVMFuzzerTestOneInput will never have a parent in the calltree. As such, we 
            # check here if the function has been hit, and if so, make it green. We avoid
            # hardcoding LLVMFuzzerTestOneInput to be green because some fuzzers may not
            # have a single seed, and in this specific case LLVMFuzzerTestOneInput
            # will be red.
            if not demangled_name == "LLVMFuzzerTestOneInput":
                l.error("LLVMFuzzerTestOneInput must be the first node in the calltree")
                exit(1)
            coverage_data = profile.get_function_coverage("LLVMFuzzerTestOneInput")
            if len(coverage_data) == 0:
                l.error("There is no coverage data (not even all negative).")
                #exit(0)
            node['cov-parent'] = "EP"

            node_hitcount = 0
            for (n_line_number, hit_count_cov) in coverage_data:
                node_hitcount = max(hit_count_cov, node_hitcount)
            is_first = False
        elif  callstack_has_parent(node, callstack):
            # Find the parent function and check coverage of the node
            coverage_data = profile.get_function_coverage(fuzz_utils.normalise_str(callstack_get_parent(node, callstack)), True)
            for (n_line_number, hit_count_cov) in coverage_data:
                if n_line_number == node['linenumber'] and hit_count_cov > 0:
                    node_hitcount = hit_count_cov
            node['cov-parent'] = callstack_get_parent(node, callstack)
        else:
            l.error("A node should either be the first or it must have a parent")
            exit(1)
        node['cov-hitcount'] = node_hitcount

        # Map hitcount to color of target.
        def get_hit_count_color(hit_count):
            color_schemes = [ (0,1,"red"), (1, 10, "gold"), (10, 30, "yellow"),
                    (30, 50, "greenyellow"), (50, 1000000000000, "lawngreen") ]
            for cmin, cmax, cname in color_schemes:
                if hit_count >= cmin and hit_count < cmax:
                    return cname
            return "red"
        color_to_be = get_hit_count_color(node['cov-hitcount'])
        node['cov-color'] = color_to_be


        # Get URL to coverage report for the node.
        link = "#"
        for fd_k, fd in project_profile.all_functions.items():
            if fd.function_name == node['function_name']:
                link = coverage_url + \
                    "%s.html#L%d" % (
                        fd.function_source_file, fd.function_linenumber)
                break
        node['cov-link'] = link

        # Find the parent
        callsite_link = "#"
        if callstack_has_parent(node, callstack):
            parent_fname = callstack_get_parent(node, callstack)
            for fd_k, fd in project_profile.all_functions.items():
                if fuzz_utils.demangle_cpp_func(fd.function_name) == parent_fname:
                    callsite_link = coverage_url + "%s.html#L%d" % (
                            fd.function_source_file,   # parent source file
                            node['linenumber'])        # callsite line number
        node['cov-callsite-link'] = callsite_link

        # Get the Github URL to the node. However, if we got a "/" basefolder it means
        # it is a wrong basefolder and we handle this by removing the two first folders
        # in the complete path (which shuold be in most cases /src/NAME where NAME
        # is the project folder.
        if basefolder == "/":
            fd_github_url = "%s/%s#L%d" % (git_repo_url, "/".join(
                fd.function_source_file.split("/")[3:]), fd.function_linenumber)
        else:
            fd_github_url = "%s/%s#L%d" % (git_repo_url, fd.function_source_file.replace(
                basefolder, ""), fd.function_linenumber)
        node['cov-github-url'] = fd_github_url

    # Extract data about which nodes unlocks data
    for idx1 in range(len(profile.function_call_depths)):
        n1 = profile.function_call_depths[idx1]
        if n1['cov-hitcount'] == 0:
            n1['cov-forward-reds'] = 0
            n1['cov-largest-blocked-func'] = "none"
            continue

        # Read forward untill we see a green node. Depth must be the same or higher
        idx2 = idx1+1
        forward_red = 0
        largest_blocked_name = ""
        largest_blocked_count = 0
        while idx2 < len(profile.function_call_depths):
            # Check if we should break or increment forward_red
            n2 = profile.function_call_depths[idx2]

            # Break if the node is not at depth or deeper in the calltree than n1
            # Remember:
            # - the lower the depth, the higher up (closer to LLVMFuzzerTestOneInput) in the calltree
            # - the higehr the depth, the lower down (further away from LLVMFuzzerTestOneInput) in the calltree
            if n2['depth'] < n1['depth']:
                break

            # break if the node is visited. We *could* change this to another metric, e.g.
            # all nodes underneath n1 that are off, i.e. instead of breaking here we would
            # increment forward_red iff cov-hitcount != 0. This, however, would prioritise
            # blockers at the top rather than precisely locate them in the calltree.
            if n2['cov-hitcount'] != 0:
                break

            for fd_k, fd in project_profile.all_functions.items():
                if fuzz_utils.demangle_cpp_func(fd.function_name) == n2['function_name'] and fd.total_cyclomatic_complexity > largest_blocked_count:
                    largest_blocked_count = fd.total_cyclomatic_complexity
                    largest_blocked_name = n2['function_name']
                    break

            forward_red += 1
            idx2 += 1

        n1['cov-forward-reds'] = forward_red
        n1['cov-largest-blocked-func'] = largest_blocked_name



def analysis_get_optimal_targets(
        merged_profile: fuzz_data_loader.MergedProjectProfile) -> Tuple[List[fuzz_data_loader.FuzzerProfile], Set[str]]:
    """
    Finds the top reachable functions with minimum overlap.
    Each of these functions is not be reachable by another function
    in the returned set, but, they may reach some of the same functions.
    """
    l.info("    - in analysis_get_optimal_targets")
    optimal_set = set()
    target_fds = list()
    #for fd in reversed(sorted(merged_profile.all_functions, key=lambda x: len(x['functionsReached']))):
    for fd in reversed(sorted(list(merged_profile.all_functions.values()), key=lambda x: len(x.functions_reached))):
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
    l.info(". Done")
    return target_fds, optimal_set


def analysis_synthesize_simple_targets(
        merged_profile: fuzz_data_loader.MergedProjectProfile) -> (
                Tuple[Dict[str, Dict[str, Any]],
                      fuzz_data_loader.MergedProjectProfile,
                      List[fuzz_data_loader.FuzzerProfile]]):
    '''
    Function for synthesizing fuzz targets. The way this one works is by finding
    optimal targets that don't overlap too much with each other. The fuzz targets
    are created to target functions in specific files, so all functions targeted 
    in each fuzzer will be from the same source file.

    In a sense, this is more of a PoC wy to do some analysis on the data we have.
    It is likely that we could do something much better.
    '''
    l.info("  - in analysis_synthesize_simple_targets")
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
        l.info("  - sorting by unreached complexity. ")
        sorted_by_undiscovered_complexity = list(reversed(sorted(target_fds, key=lambda x: int(x.new_unreached_complexity))))
        l.info(". Done")

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
        if tfd.new_unreached_complexity <= 35:
            break
        #if to_continue:
        curr_count += 1

        optimal_functions_targeted.append(tfd)

        code = ""
        code_var_decl = ""
        variable_creation = ""
        var_order = []
        for arg_type in tfd.arg_types:
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
        code += "  /* target %s */\n"%(tfd.function_name)
        #code += "  /* linkage %s */\n"%(tfd['linkageType'])
        code += code_var_decl
        code += "  %s("%(tfd.function_name)
        for idx in range(len(var_order)):
            code += var_order[idx]
            if idx < (len(var_order)-1):
                code += ", "
        code += ");\n"
        code += "\n"
        if tfd.function_source_file not in target_codes:
            target_codes[tfd.function_source_file] = dict()
            target_codes[tfd.function_source_file]['source_code'] = ""
            target_codes[tfd.function_source_file]['target_fds'] = list()

        #print("[Fuzz synthesizer] Function %s - adding code: %s"%(tfd['functionName'], code))
        target_codes[tfd.function_source_file]['source_code'] += code
        target_codes[tfd.function_source_file]['target_fds'].append(tfd)


        l.info("  - calling add_func_t_reached_and_clone. ")
        new_merged_profile = fuzz_data_loader.add_func_to_reached_and_clone(new_merged_profile, tfd)

        # Ensure hitcount is set
        tmp_ff = new_merged_profile.all_functions[tfd.function_name]
        if tmp_ff.hitcount == 0:
            l.info("Error. Hitcount did not get set for some reason. Exiting")
            exit(0)
        l.info(". Done")

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

    l.info("Found the following optimal functions: { %s }"%(
        str([f.function_name for f in optimal_functions_targeted])))

    return final_fuzzers, new_merged_profile, optimal_functions_targeted

def analysis_coverage_runtime_analysis(
        profiles : List[fuzz_data_loader.FuzzerProfile],
        merged_profile : fuzz_data_loader.MergedProjectProfile):
    """
    Identifies the functions that are hit in terms of coverage, but
    only has a low percentage overage in terms of lines covered in the
    target program.
    This is useful to highlight functions that need inspection and is
    in contrast to statically-extracted data which gives a hit/not-hit
    verdict on a given function entirely.
    """
    print("In coverage optimal analysis")

    # Find all functions that satisfy:
    # - source lines above 50
    # - less than 15% coverage
    functions_of_interest = []
    for funcname in merged_profile.runtime_coverage.hit_summary:
        try:
            hit_summary = merged_profile.runtime_coverage.hit_summary[funcname]
            hit_proportion = (hit_summary['hit-lines'] / hit_summary['total-lines']) * 100.0
            if hit_summary['total-lines'] > 50 and hit_proportion < 20:
                functions_of_interest.append(funcname)
        except:
            l.error("Error getting hit-summary information for %s"%(funcname))

    return functions_of_interest
