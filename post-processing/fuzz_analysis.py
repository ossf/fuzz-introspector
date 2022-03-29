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

import copy
import logging

from typing import (
    Dict,
    List,
    Set,
    Tuple,
    TypedDict,
)

import fuzz_utils
import fuzz_cfg_load
import fuzz_data_loader

logger = logging.getLogger(name=__name__)

TargetCodesType = TypedDict('TargetCodesType', {
    'source_code': str,
    'target_fds': List[fuzz_data_loader.FunctionProfile]
})


def overlay_calltree_with_coverage(
        profile: fuzz_data_loader.FuzzerProfile,
        project_profile: fuzz_data_loader.MergedProjectProfile,
        coverage_url: str,
        git_repo_url: str,
        basefolder: str) -> None:
    # We use the callstack to keep track of all function parents. We need this
    # when looking up if a callsite was hit or not. This is because the coverage
    # information about a callsite is located in coverage data of the function
    # in which the callsite is placed.
    callstack: Dict[int, str] = dict()

    def callstack_get_parent(n, c):
        return c[int(n.depth) - 1]

    def callstack_has_parent(n, c):
        return int(n.depth) - 1 in c

    def callstack_set_curr_node(n, name, c):
        c[int(node.depth)] = name

    is_first = True
    ct_idx = 0
    if profile.function_call_depths is None:
        return
    for node in fuzz_cfg_load.extract_all_callsites(profile.function_call_depths):
        node.cov_ct_idx = ct_idx
        ct_idx += 1

        demangled_name = fuzz_utils.demangle_cpp_func(node.dst_function_name)

        # Add to callstack
        callstack_set_curr_node(node, demangled_name, callstack)

        logger.info(f"Checking callsite: { demangled_name}")

        # Get hitcount for this node
        node_hitcount: int = 0
        if is_first:
            # The first node is always the entry of LLVMFuzzerTestOneInput
            # LLVMFuzzerTestOneInput will never have a parent in the calltree. As such, we
            # check here if the function has been hit, and if so, make it green. We avoid
            # hardcoding LLVMFuzzerTestOneInput to be green because some fuzzers may not
            # have a single seed, and in this specific case LLVMFuzzerTestOneInput
            # will be red.
            if not demangled_name == "LLVMFuzzerTestOneInput":
                logger.error("LLVMFuzzerTestOneInput must be the first node in the calltree")
                exit(1)
            coverage_data = profile.get_function_coverage("LLVMFuzzerTestOneInput")
            if len(coverage_data) == 0:
                logger.error("There is no coverage data (not even all negative).")
            node.cov_parent = "EP"

            node_hitcount = 0
            for (n_line_number, hit_count_cov) in coverage_data:
                node_hitcount = max(hit_count_cov, node_hitcount)
            is_first = False
        elif callstack_has_parent(node, callstack):
            # Find the parent function and check coverage of the node
            logger.info("Extracting data")
            coverage_data = profile.get_function_coverage(
                fuzz_utils.normalise_str(callstack_get_parent(node, callstack)),
                True
            )
            for (n_line_number, hit_count_cov) in coverage_data:
                logger.info(f"  - iterating {n_line_number} : {hit_count_cov}")
                if n_line_number == node.src_linenumber and hit_count_cov > 0:
                    node_hitcount = hit_count_cov
            node.cov_parent = callstack_get_parent(node, callstack)
        else:
            logger.error("A node should either be the first or it must have a parent")
            exit(1)
        node.cov_hitcount = node_hitcount

        # Map hitcount to color of target.
        def get_hit_count_color(hit_count):
            color_schemes = [
                (0, 1, "red"),
                (1, 10, "gold"),
                (10, 30, "yellow"),
                (30, 50, "greenyellow"),
                (50, 1000000000000, "lawngreen")]
            for cmin, cmax, cname in color_schemes:
                if hit_count >= cmin and hit_count < cmax:
                    return cname
            return "red"
        color_to_be = get_hit_count_color(node.cov_hitcount)
        node.cov_color = color_to_be

        # Get URL to coverage report for the node.
        link = "#"
        for fd_k, fd in profile.all_class_functions.items():
            if fd.function_name == node.dst_function_name:
                link = coverage_url + \
                    "%s.html#L%d" % (
                        fd.function_source_file, fd.function_linenumber)
                break
        node.cov_link = link

        # Find the parent
        callsite_link = "#"
        if callstack_has_parent(node, callstack):
            parent_fname = callstack_get_parent(node, callstack)
            for fd_k, fd in profile.all_class_functions.items():
                if fuzz_utils.demangle_cpp_func(fd.function_name) == parent_fname:
                    callsite_link = coverage_url + "%s.html#L%d" % (
                        fd.function_source_file,   # parent source file
                        node.src_linenumber)       # callsite line number
        node.cov_callsite_link = callsite_link

    # Extract data about which nodes unlocks data
    all_callsites = fuzz_cfg_load.extract_all_callsites(profile.function_call_depths)
    prev_end = -1
    for idx1 in range(len(all_callsites)):
        n1 = all_callsites[idx1]
        prev = None
        if idx1 > 0:
            prev = all_callsites[idx1 - 1]
        if n1.cov_hitcount == 0 and (
                (prev is not None and prev.depth <= n1.depth) or idx1 < prev_end):
            n1.cov_forward_reds = 0
            n1.cov_largest_blocked_func = "none"
            continue

        # Read forward untill we see a green node. Depth must be the same or higher
        idx2 = idx1 + 1
        forward_red = 0
        largest_blocked_name = ""
        largest_blocked_count = 0
        while idx2 < len(all_callsites):
            # Check if we should break or increment forward_red
            n2 = all_callsites[idx2]

            # Break if the node is not at depth or deeper in the calltree than n1
            # Remember:
            # - the lower the depth, the higher up (closer to LLVMFuzzerTestOneInput) in the
            #   calltree
            # - the higehr the depth, the lower down (further away from LLVMFuzzerTestOneInput)
            #   in the calltree
            if n2.depth < n1.depth:
                break

            # break if the node is visited. We *could* change this to another metric, e.g.
            # all nodes underneath n1 that are off, i.e. instead of breaking here we would
            # increment forward_red iff cov-hitcount != 0. This, however, would prioritise
            # blockers at the top rather than precisely locate them in the calltree.
            if n2.cov_hitcount != 0:
                break

            for fd_k, fd in project_profile.all_functions.items():
                if (
                    fuzz_utils.demangle_cpp_func(fd.function_name) == n2.dst_function_name
                    and fd.total_cyclomatic_complexity > largest_blocked_count
                ):
                    largest_blocked_count = fd.total_cyclomatic_complexity
                    largest_blocked_name = n2.dst_function_name
                    break

            forward_red += 1
            idx2 += 1
        prev_end = idx2 - 1
        # logger.info("Assigning forward red: %d for index %d"%(forward_red, idx1))
        n1.cov_forward_reds = forward_red
        n1.cov_largest_blocked_func = largest_blocked_name


def analysis_get_optimal_targets(
    merged_profile: fuzz_data_loader.MergedProjectProfile
) -> Tuple[List[fuzz_data_loader.FunctionProfile], Set[str]]:
    """
    Finds the top reachable functions with minimum overlap.
    Each of these functions is not be reachable by another function
    in the returned set, but, they may reach some of the same functions.
    """
    logger.info("    - in analysis_get_optimal_targets")
    optimal_set: Set[str] = set()
    target_fds: List[fuzz_data_loader.FunctionProfile] = list()

    for fd in reversed(sorted(list(merged_profile.all_functions.values()),
                              key=lambda x: len(x.functions_reached))):
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
        # proportion = (total_vals*1.0)/(len(fd['functionsReached'])*1.0)

        # if proportion == 1.0:
        #    continue

        # condition1 = proportion < 0.5
        condition1 = True

        # We also want to include all targets that have a fairly high complexity.
        condition2 = fd.bb_count > 1

        if not (condition1 or condition2):
            continue

        for func_name in fd.functions_reached:
            optimal_set.add(func_name)

        target_fds.append(fd)
    logger.info(". Done")
    return target_fds, optimal_set


def analysis_synthesize_simple_targets(
        merged_profile: fuzz_data_loader.MergedProjectProfile) -> (
            Tuple[
                Dict[str, TargetCodesType],
                fuzz_data_loader.MergedProjectProfile,
                List[fuzz_data_loader.FunctionProfile]
            ]):
    '''
    Function for synthesizing fuzz targets. The way this one works is by finding
    optimal targets that don't overlap too much with each other. The fuzz targets
    are created to target functions in specific files, so all functions targeted
    in each fuzzer will be from the same source file.

    In a sense, this is more of a PoC wy to do some analysis on the data we have.
    It is likely that we could do something much better.
    '''
    logger.info("  - in analysis_synthesize_simple_targets")
    new_merged_profile = copy.deepcopy(merged_profile)
    target_fds, optimal_set = analysis_get_optimal_targets(merged_profile)
    fuzzer_code = "#include \"ada_fuzz_header.h\"\n"
    fuzzer_code += "\n"
    fuzzer_code += "int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n"
    fuzzer_code += "  af_safe_gb_init(data, size);\n\n"

    target_codes: Dict[str, TargetCodesType] = dict()
    optimal_functions_targeted: List[fuzz_data_loader.FunctionProfile] = []

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
    curr_count = 0
    while curr_count < max_count:
        logger.info("  - sorting by unreached complexity. ")
        sorted_by_undiscovered_complexity = list(reversed(sorted(target_fds,
                                                                 key=lambda x: int(
                                                                     x.new_unreached_complexity))))
        logger.info(". Done")

        try:
            tfd = sorted_by_undiscovered_complexity[0]
        except Exception:
            break
        if tfd is None:
            break

        if tfd.new_unreached_complexity <= 35:
            break
        curr_count += 1

        optimal_functions_targeted.append(tfd)

        code = ""
        code_var_decl = ""
        var_order = []
        for arg_type in tfd.arg_types:
            arg_type = arg_type.replace(" ", "")
            if arg_type == "char**":
                code_var_decl += "  char **new_var%d = af_get_double_char_p();\n" % var_idx
                # We dont want the below line but instead we want to ensure
                # we always return something valid.
                var_order.append("new_var%d" % var_idx)
                var_idx += 1
            elif arg_type == "char*":
                code_var_decl += "  char *new_var%d = ada_safe_get_char_p();\n" % var_idx
                var_order.append("new_var%d" % var_idx)
                var_idx += 1
            elif arg_type == "int":
                code_var_decl += "  int new_var%d = ada_safe_get_int();\n" % var_idx
                var_order.append("new_var%d" % var_idx)
                var_idx += 1
            elif arg_type == "int*":
                code_var_decl += "  int *new_var%d = af_get_int_p();\n" % var_idx
                var_order.append("new_var%d" % var_idx)
                var_idx += 1
            elif "struct" in arg_type and "*" in arg_type and "**" not in arg_type:
                code_var_decl += "  %s new_var%d = calloc(sizeof(%s), 1);\n" % (
                    arg_type.replace(".", " "),
                    var_idx,
                    arg_type.replace(".", " ").replace("*", ""))
                var_order.append("new_var%d" % var_idx)
                var_idx += 1
            else:
                code_var_decl += "  UNKNOWN_TYPE unknown_%d;\n" % var_idx
                var_order.append("unknown_%d" % var_idx)
                var_idx += 1

        # Now add the function call.
        code += "  /* target %s */\n" % tfd.function_name
        code += code_var_decl
        code += "  %s(" % tfd.function_name
        for idx in range(len(var_order)):
            code += var_order[idx]
            if idx < (len(var_order) - 1):
                code += ", "
        code += ");\n"
        code += "\n"
        if tfd.function_source_file not in target_codes:
            target_codes[tfd.function_source_file] = {
                'source_code': "",
                'target_fds': list()
            }
        target_codes[tfd.function_source_file]['source_code'] += code
        target_codes[tfd.function_source_file]['target_fds'].append(tfd)

        logger.info("  - calling add_func_t_reached_and_clone. ")
        new_merged_profile = fuzz_data_loader.add_func_to_reached_and_clone(new_merged_profile, tfd)

        # Ensure hitcount is set
        tmp_ff = new_merged_profile.all_functions[tfd.function_name]
        if tmp_ff.hitcount == 0:
            logger.info("Error. Hitcount did not get set for some reason. Exiting")
            exit(0)
        logger.info(". Done")

        # We need to update the optimal targets here.
        # We only need to do this operation if we are actually going to continue analysis

        if curr_count < max_count:
            target_fds, optimal_set = analysis_get_optimal_targets(new_merged_profile)

    final_fuzzers: Dict[str, TargetCodesType] = dict()
    for filename in target_codes:
        file_fuzzer_code = fuzzer_code
        file_fuzzer_code += target_codes[filename]['source_code']
        file_fuzzer_code += "  af_safe_gb_cleanup();\n"
        file_fuzzer_code += "}\n"

        final_fuzzers[filename] = {
            'source_code': file_fuzzer_code,
            'target_fds': target_codes[filename]['target_fds']
        }

    logger.info("Found the following optimal functions: { %s }" % (
        str([f.function_name for f in optimal_functions_targeted])))

    return final_fuzzers, new_merged_profile, optimal_functions_targeted


def analysis_coverage_runtime_analysis(
        profiles: List[fuzz_data_loader.FuzzerProfile],
        merged_profile: fuzz_data_loader.MergedProjectProfile):
    """
    Identifies the functions that are hit in terms of coverage, but
    only has a low percentage overage in terms of lines covered in the
    target program.
    This is useful to highlight functions that need inspection and is
    in contrast to statically-extracted data which gives a hit/not-hit
    verdict on a given function entirely.
    """
    logger.info("In coverage optimal analysis")

    # Find all functions that satisfy:
    # - source lines above 50
    # - less than 15% coverage
    functions_of_interest = []
    for funcname in merged_profile.runtime_coverage.get_all_hit_functions():
        try:
            total_lines, hit_lines = merged_profile.runtime_coverage.get_hit_summary(funcname)
            hit_proportion = (hit_lines / total_lines) * 100.0
            if total_lines > 50 and hit_proportion < 20:
                functions_of_interest.append(funcname)
        except Exception:
            logger.error("Error getting hit-summary information for %s" % funcname)
    return functions_of_interest
