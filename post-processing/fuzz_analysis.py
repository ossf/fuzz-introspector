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

import abc
import logging

from typing import (
    Dict,
    List,
    Tuple,
)

import fuzz_utils
import fuzz_cfg_load
import fuzz_data_loader

logger = logging.getLogger(name=__name__)
logger.setLevel(logging.INFO)


class AnalysisInterface(abc.ABC):
    name: str

    @abc.abstractmethod
    def analysis_func(self,
                      toc_list: List[Tuple[str, str, int]],
                      tables: List[str],
                      project_profile: fuzz_data_loader.MergedProjectProfile,
                      profiles: List[fuzz_data_loader.FuzzerProfile],
                      basefolder: str,
                      coverage_url: str,
                      conclusions) -> str:
        """Core analysis function."""
        pass


def get_all_analyses() -> List[AnalysisInterface]:
    # Ordering here is important as top analysis will be shown first in the report
    from analyses import (
        fuzz_driver_synthesizer,
        fuzz_engine_input,
        fuzz_optimal_targets,
        fuzz_runtime_coverage_analysis,
    )

    analysis_array = [
        fuzz_optimal_targets.FuzzOptimalTargetAnalysis(),
        fuzz_engine_input.FuzzEngineInputAnalysis(),
        fuzz_runtime_coverage_analysis.FuzzRuntimeCoverageAnalysis(),
        fuzz_driver_synthesizer.FuzzDriverSynthesizerAnalysis()
    ]
    return analysis_array


def overlay_calltree_with_coverage(
        profile: fuzz_data_loader.FuzzerProfile,
        project_profile: fuzz_data_loader.MergedProjectProfile,
        coverage_url: str,
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

    target_name = profile.get_key()
    target_coverage_url = fuzz_utils.get_target_coverage_url(coverage_url, target_name)
    logger.info(f"Using coverage url: {target_coverage_url}")

    for node in fuzz_cfg_load.extract_all_callsites(profile.function_call_depths):
        node.cov_ct_idx = ct_idx
        ct_idx += 1

        demangled_name = fuzz_utils.demangle_cpp_func(node.dst_function_name)

        # Add to callstack
        callstack_set_curr_node(node, demangled_name, callstack)

        logger.debug(f"Checking callsite: { demangled_name}")

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
            logger.debug("Extracting data")
            coverage_data = profile.get_function_coverage(
                fuzz_utils.normalise_str(callstack_get_parent(node, callstack)),
                True
            )
            for (n_line_number, hit_count_cov) in coverage_data:
                logger.debug(f"  - iterating {n_line_number} : {hit_count_cov}")
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
                link = (
                    f"{target_coverage_url}"
                    f"{fd.function_source_file}.html#L{fd.function_linenumber}"
                )
                break
        node.cov_link = link

        # Find the parent
        callsite_link = "#"
        if callstack_has_parent(node, callstack):
            parent_fname = callstack_get_parent(node, callstack)
            for fd_k, fd in profile.all_class_functions.items():
                if fuzz_utils.demangle_cpp_func(fd.function_name) == parent_fname:
                    callsite_link = (
                        f"{target_coverage_url}"
                        f"{fd.function_source_file}.html#L{node.src_linenumber}"
                    )
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

        # Read forward untill we see a green node.
        idx2 = idx1 + 1
        forward_red = 0
        largest_blocked_name = ""
        largest_blocked_count = 0
        while idx2 < len(all_callsites):
            # Check if we should break or increment forward_red
            n2 = all_callsites[idx2]

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
        logger.debug(f"Going through {funcname}")

        total_lines, hit_lines = merged_profile.runtime_coverage.get_hit_summary(funcname)
        logger.debug(f"Total lines: {total_lines} -- hit_lines: {hit_lines}")
        try:
            hit_proportion = (hit_lines / total_lines) * 100.0
            logger.debug(f"hit proportion {hit_proportion}")
            if total_lines > 30 and hit_proportion < 55:
                functions_of_interest.append(funcname)
        except Exception:
            logger.error(f"Error getting hit-summary information for {funcname}")
    return functions_of_interest
