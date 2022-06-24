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
import fuzz_cov_load
from enum import Enum

from exceptions import AnalysisError

logger = logging.getLogger(name=__name__)
logger.setLevel(logging.INFO)


class AnalysisInterface(abc.ABC):
    name: str

    @abc.abstractmethod
    def analysis_func(
        self,
        toc_list: List[Tuple[str, str, int]],
        tables: List[str],
        project_profile: fuzz_data_loader.MergedProjectProfile,
        profiles: List[fuzz_data_loader.FuzzerProfile],
        basefolder: str,
        coverage_url: str,
        conclusions: List[Tuple[int, str]]
    ) -> str:
        """Core analysis function."""
        pass


class BlockedSide(Enum):
    TRUE = 1
    FALSE = 2


class FuzzBranchBlocker:
    def __init__(self, side, not_cov_comp, reach_comp, filename, b_line, s_line, fname) -> None:
        self.blocked_side = side
        self.blocked_not_covered_complexity = not_cov_comp
        self.blocked_reachable_complexity = reach_comp
        self.source_file_name = filename
        self.branch_line_number = b_line
        self.blocked_side_line_numder = s_line
        self.function_name = fname


def get_all_analyses() -> List[AnalysisInterface]:
    # Ordering here is important as top analysis will be shown first in the report
    from analyses import (
        fuzz_driver_synthesizer,
        fuzz_engine_input,
        fuzz_optimal_targets,
        fuzz_runtime_coverage_analysis,
        fuzz_bug_digestor
    )

    analysis_array = [
        fuzz_optimal_targets.FuzzOptimalTargetAnalysis(),
        fuzz_engine_input.FuzzEngineInputAnalysis(),
        fuzz_runtime_coverage_analysis.FuzzRuntimeCoverageAnalysis(),
        fuzz_driver_synthesizer.FuzzDriverSynthesizerAnalysis(),
        fuzz_bug_digestor.FuzzBugDigestorAnalysis()
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

    if profile.coverage is None:
        return

    def callstack_get_parent(
        n: fuzz_cfg_load.CalltreeCallsite,
        c: Dict[int, str]
    ) -> str:
        return c[int(n.depth) - 1]

    def callstack_has_parent(
        n: fuzz_cfg_load.CalltreeCallsite,
        c: Dict[int, str]
    ) -> bool:
        return int(n.depth) - 1 in c

    def callstack_set_curr_node(
        n: fuzz_cfg_load.CalltreeCallsite,
        name: str,
        c: Dict[int, str]
    ) -> None:
        c[int(n.depth)] = name

    is_first = True
    ct_idx = 0
    if profile.function_call_depths is None:
        return

    target_name = profile.get_key()
    target_coverage_url = fuzz_utils.get_target_coverage_url(
        coverage_url,
        target_name,
        profile.target_lang
    )
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
            if demangled_name != "LLVMFuzzerTestOneInput" and "TestOneInput" not in demangled_name:
                logger.info("Unexpected first node in the calltree.")
                logger.info(f"Found: {demangled_name}")
                raise AnalysisError(
                    "First node in calltree seems to be non-fuzzer function"
                )
            coverage_data = profile.coverage.get_hit_details("LLVMFuzzerTestOneInput")
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
            logger.info(
                f"Getting hit details {node.dst_function_name} -- "
                f"{node.cov_ct_idx} -- {node.src_linenumber}"
            )
            if profile.target_lang == "python":
                ih = profile.coverage.generic_check_hit(
                    callstack_get_parent(node, callstack),
                    node.src_linenumber,
                    True
                )
                if ih:
                    node_hitcount = 200
            else:
                coverage_data = profile.coverage.get_hit_details(
                    callstack_get_parent(node, callstack)
                )
                for (n_line_number, hit_count_cov) in coverage_data:
                    logger.debug(f"  - iterating {n_line_number} : {hit_count_cov}")
                    if n_line_number == node.src_linenumber and hit_count_cov > 0:
                        node_hitcount = hit_count_cov
            node.cov_parent = callstack_get_parent(node, callstack)
        else:
            logger.error("A node should either be the first or it must have a parent")
            raise AnalysisError(
                "A node should either be the first or it must have a parent"
            )
        node.cov_hitcount = node_hitcount

        # Map hitcount to color of target.
        def get_hit_count_color(hit_count: int) -> str:
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
                logger.debug("Found %s -- %s -- %d" % (
                    fd.function_name,
                    fd.function_source_file,
                    fd.function_linenumber
                ))
                link = profile.resolve_coverage_link(
                    target_coverage_url,
                    fd.function_source_file,
                    fd.function_linenumber,
                    fd.function_name
                )
                break
        node.cov_link = link

        # Find the parent
        callsite_link = "#"
        if callstack_has_parent(node, callstack):
            parent_fname = callstack_get_parent(node, callstack)
            for fd_k, fd in profile.all_class_functions.items():
                if fuzz_utils.demangle_cpp_func(fd.function_name) == parent_fname:
                    callsite_link = profile.resolve_coverage_link(
                        target_coverage_url,
                        fd.function_source_file,
                        node.src_linenumber,
                        fd.function_name
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

    update_branch_complexities(profile.all_class_functions, profile.coverage)
    branch_blockers = detect_branch_level_blockers(profile)
    logger.info(f"[+] found {len(branch_blockers)} branch blockers.")
    # TODO: use these results appropriately ...
    branch_blockers_list = []
    for br_blocker in branch_blockers[:10]:
        branch_blockers_list.append(
            {
                'blocked_side': repr(br_blocker.blocked_side),
                'blocked_not_covered_complexity': br_blocker.blocked_not_covered_complexity,
                'blocked_reachable_complexity': br_blocker.blocked_reachable_complexity,
                'source_file_name': br_blocker.source_file_name,
                'branch_line_number': br_blocker.branch_line_number,
                'blocked_side_line_numder': br_blocker.blocked_side_line_numder,
                'function_name': br_blocker.function_name
            }
        )
    fuzz_utils.write_to_summary_file(profile.get_key(), 'branch_blockers', branch_blockers_list)


def update_branch_complexities(all_functions: Dict[str, fuzz_data_loader.FunctionProfile],
                               coverage: fuzz_cov_load.CoverageProfile) -> None:
    """
    Traverse every branch profile and update the side complexities based on reached funcs
    complexity.
    """
    # for branch_k, branch in branch_profiles.items():
    for func_k, func in all_functions.items():
        for branch_k, branch in func.branch_profiles.items():
            branch.branch_false_side_reachable_complexity = 0
            branch.branch_true_side_reachable_complexity = 0
            branch.branch_false_side_not_covered_complexity = 0
            branch.branch_true_side_not_covered_complexity = 0
            for fn in branch.branch_false_side_funcs:
                if fn not in all_functions:
                    continue
                branch.branch_false_side_reachable_complexity += (
                    all_functions[fn].total_cyclomatic_complexity)
                if coverage.is_func_hit(fn) is False:
                    branch.branch_false_side_not_covered_complexity += (
                        all_functions[fn].total_cyclomatic_complexity)

            for fn in branch.branch_true_side_funcs:
                if fn not in all_functions:
                    continue
                branch.branch_true_side_reachable_complexity += (
                    all_functions[fn].total_cyclomatic_complexity)
                if coverage.is_func_hit(fn) is False:
                    branch.branch_true_side_not_covered_complexity += (
                        all_functions[fn].total_cyclomatic_complexity)


def detect_branch_level_blockers(
    fuzz_profile: fuzz_data_loader.FuzzerProfile
) -> List[FuzzBranchBlocker]:
    fuzz_blockers = []

    if fuzz_profile.coverage is None:
        logger.error(f"No coverage for fuzzer {fuzz_profile.binary_executable}."
                     "Skipping branch blocker detection.")
        return []
    coverage = fuzz_profile.coverage
    functions_profile = fuzz_profile.all_class_functions

    for branch_string in coverage.branch_cov_map:
        blocked_side = None
        true_hitcount, false_hitcount = coverage.branch_cov_map[branch_string]

        # Catch exceptions in case some of the string splitting fails
        try:
            function_name, rest_string = branch_string.split(':')
            line_number, column_number = rest_string.split(',')
        except ValueError:
            logger.error("branch-profiling: error getting function name")
            continue

        if function_name not in functions_profile:
            logger.error("branch-profiling: func name not in functions_profile")
            continue

        llvm_branch_profile = functions_profile[function_name].branch_profiles
        # Just extract the file name and skip the path
        source_file_name = functions_profile[function_name].function_source_file.split('/')[-1]
        llvm_branch_string = f'{source_file_name}:{line_number},{column_number}'

        if llvm_branch_string not in llvm_branch_profile:
            # TODO: there are cases that the column number of the branch is not consistent between
            # llvm and coverage debug info. For now we skip those cases.
            # logger.info(f"[X][X] debug: failed to find branch profile for {llvm_branch_string}")
            continue

        llvm_branch = llvm_branch_profile[llvm_branch_string]
        # For now this checks for not-taken branch sides, instead
        # it may become interesting to report less-taken side: like
        # the side that is taken less than 20% of the times
        if true_hitcount == 0 and false_hitcount != 0:
            blocked_side = BlockedSide.TRUE
            blocked_reachable_complexity = llvm_branch.branch_true_side_reachable_complexity
            blocked_not_covered_complexity = llvm_branch.branch_true_side_not_covered_complexity
            side_line = llvm_branch.branch_true_side_pos
            side_line_number = side_line.split(':')[1].split(',')[0]
        elif true_hitcount != 0 and false_hitcount == 0:
            blocked_side = BlockedSide.FALSE
            blocked_reachable_complexity = llvm_branch.branch_false_side_reachable_complexity
            blocked_not_covered_complexity = llvm_branch.branch_false_side_not_covered_complexity
            side_line = llvm_branch.branch_false_side_pos
            side_line_number = side_line.split(':')[1].split(',')[0]

        if blocked_side:
            fuzz_blockers.append(FuzzBranchBlocker(blocked_side, blocked_not_covered_complexity,
                                 blocked_reachable_complexity, source_file_name, line_number,
                                 side_line_number, function_name))

    fuzz_blockers.sort(key=lambda x: [x.blocked_not_covered_complexity,
                                      x.blocked_reachable_complexity], reverse=True)
    return fuzz_blockers
