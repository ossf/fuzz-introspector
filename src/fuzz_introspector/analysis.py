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
import multiprocessing
import os
import shutil

from typing import (
    Dict,
    List,
    Type,
    Set,
)

from fuzz_introspector import (cfg_load, code_coverage, constants, data_loader,
                               debug_info, html_helpers, json_report, utils)

from fuzz_introspector.datatypes import (
    project_profile,
    fuzzer_profile,
    function_profile,
)
from fuzz_introspector.exceptions import AnalysisError, DataLoaderError

logger = logging.getLogger(name=__name__)


class IntrospectionProject():
    """Wrapper class for managing Fuzz Introspector analysis.

    The most important two elments of this class are
    `proj_profile` which is type :py:class:`project_profile.MergedProjectProfile` and
    `profiles` which is a list of :py:class:`fuzzer_profile.FuzzerProfile` and
    references the individual fuzzers of the given module. All analysis is done
    basically by way of these two elements.
    """

    def __init__(self, language, target_folder, coverage_url):
        self.debug_report = None
        self.language = language
        self.base_folder = target_folder
        self.coverage_url = coverage_url

    def load_data_files(self, parallelise=True, correlation_file=None):
        """Generates the `proj_profile` and `profiles` elements of this class
        based on the raw data given as arguments. This function must be called
        before any real use of `IntrospectionProject` can happen.
        """
        self.profiles = data_loader.load_all_profiles(self.base_folder,
                                                      self.language,
                                                      parallelise)

        logger.info(f"Found {len(self.profiles)} profiles")
        if len(self.profiles) == 0:
            logger.info("Found no profiles")
            raise DataLoaderError("No fuzzer profiles")

        self.input_bugs = data_loader.try_load_input_bugs()
        correlation_dict = utils.data_file_read_yaml(correlation_file)
        if correlation_dict is not None and "pairings" in correlation_dict:
            for profile in self.profiles:
                profile.correlate_executable_name(correlation_dict)

        logger.info("[+] Accummulating profiles")
        logger.info("Accummulating using multiprocessing")
        manager = multiprocessing.Manager()
        semaphore = multiprocessing.Semaphore(10)

        return_dict = manager.dict()

        jobs = []
        idx = 0
        for profile in self.profiles:
            p = multiprocessing.Process(
                target=fuzzer_profile.FuzzerProfile.accummulate_profile,
                args=(profile, self.base_folder, return_dict, f"uniq-{idx}",
                      semaphore))
            jobs.append(p)
            idx += 1
            p.start()
        for proc in jobs:
            proc.join()

        new_profiles = []
        for idx in return_dict:
            new_profiles.append(return_dict[idx])
        self.profiles = new_profiles

        logger.info("[+] Creating project profile")
        self.proj_profile = project_profile.MergedProjectProfile(self.profiles)
        self.proj_profile.coverage_url = self.coverage_url

        logger.info("[+] Refining profiles")
        for profile in self.profiles:
            profile.refine_paths(self.proj_profile.basefolder)

        for profile in self.profiles:
            overlay_calltree_with_coverage(profile, self.proj_profile,
                                           self.coverage_url, self.base_folder)
        # Load all debug files
        self.debug_files = data_loader.load_all_debug_files(self.base_folder)

        # Find all relevant debug information yaml files.
        self.debug_type_files = data_loader.find_all_debug_all_types_files(
            self.base_folder)
        self.debug_function_files = data_loader.find_all_debug_function_files(
            self.base_folder)

    def load_debug_report(self):
        """Load and digest debug information."""
        self.debug_report = debug_info.load_debug_report(self.debug_files)

        # Load the yaml  content of debug files holding type information and
        # function information.
        self.debug_all_types = debug_info.load_debug_all_yaml_files(
            self.debug_type_files)
        self.debug_all_functions = debug_info.load_debug_all_yaml_files(
            self.debug_function_files)

        # Index the functions based on file locations. This is useful for
        # quickly looking up debug function details based on their file
        # locations, which we can get from the function data collected by
        # the LLVM module.
        tmp_debug_functions = dict()
        no_path_debug_funcs = list()
        for func in self.debug_all_functions:
            if func['file_location'].strip() == '':
                no_path_debug_funcs.append(func)
            else:
                tmp_debug_functions[func['file_location']] = func

        # Cleanup some debug values that we know have weird names and
        # not the names fro the source.
        for debug_type in self.debug_all_types:
            if debug_type['name'] == '_Bool':
                debug_type['name'] = 'bool'

        self.debug_all_functions = no_path_debug_funcs + list(
            tmp_debug_functions.values())

        # Extract the raw function signature. This propagates types into all of
        # the debug functions.
        debug_info.correlate_debugged_function_to_debug_types(
            self.debug_all_types, self.debug_all_functions)

    def dump_debug_report(self):
        if self.debug_report is not None:
            debug_info.dump_debug_report(self.debug_report)


class AnalysisInterface(abc.ABC):
    name: str = ""
    json_string_result: str = ""
    display_html: bool = False

    @abc.abstractmethod
    def analysis_func(self,
                      table_of_contents: html_helpers.HtmlTableOfContents,
                      tables: List[str],
                      proj_profile: project_profile.MergedProjectProfile,
                      profiles: List[fuzzer_profile.FuzzerProfile],
                      basefolder: str, coverage_url: str,
                      conclusions: List[html_helpers.HTMLConclusion]) -> str:
        """Entrypoint for analysis instance. This function can have side effects
        on many of the arguments passed to it.

        :param table_of_contents: table of content list for adding sections to HTML report.
        :type table_of_contents: html_helpers.HtmlTableOfContents

        :param tables: list of table ids to be styled in the report.
        :type tables: List[str]

        :param proj_profile: project profile involved in the analysis.
        :type proj_profile: project_profile.MergedProjectProfile

        :param profiles: all fuzzer profiles involved in the current analysis.
        :type profiles: List[fuzzer_profile.FuzzerProfile]

        :param basefolder: Basefolder of the files as placed on the file system.
        :type basefolder: str

        :param coverage_url: Base coverage URL.
        :type coverage_url: str

        :param conclusions: List of high level conclusions to be shown in the final
                           report. Append to this list any conclusions that should
                           be shown at the top of the report page.
        :type conclusions: List[html_helpers.HTMLConclusion]

        :rtype: str
        :returns:  A string that corresponds to HTML that can be embedded in the
                   html report.
        """

    @classmethod
    @abc.abstractmethod
    def get_name(cls):
        """Return name of analysis"""

    @abc.abstractmethod
    def get_json_string_result(self):
        """Return json_string_result"""

    @abc.abstractmethod
    def set_json_string_result(self, string):
        """Set json_string_result"""

    def set_display_html(self, is_display_html):
        """Set display_html"""
        self.display_html = is_display_html


def instantiate_analysis_interface(cls: Type[AnalysisInterface]):
    """Wrapper function to satisfy Mypy semantics"""
    return cls()


class FuzzBranchBlocker:

    def __init__(self, side, unique_not_cov_comp, unique_reach_comp,
                 unique_funcs, not_cov_comp, reach_comp, hitcount_diff,
                 filename, b_line, s_line, fname, link) -> None:
        self.blocked_side = side
        self.blocked_unique_not_covered_complexity = unique_not_cov_comp
        self.blocked_unique_reachable_complexity = unique_reach_comp
        self.blocked_unique_funcs = unique_funcs
        self.blocked_not_covered_complexity = not_cov_comp
        self.blocked_reachable_complexity = reach_comp
        self.sides_hitcount_diff = hitcount_diff
        self.source_file = filename
        self.branch_line_number = b_line
        self.blocked_side_line_numder = s_line
        self.function_name = fname
        self.coverage_report_link = link


def get_all_analyses() -> List[Type[AnalysisInterface]]:
    from fuzz_introspector import analyses
    return analyses.all_analyses


def callstack_get_parent(n: cfg_load.CalltreeCallsite, c: Dict[int,
                                                               str]) -> str:
    return c[int(n.depth) - 1]


def callstack_has_parent(n: cfg_load.CalltreeCallsite, c: Dict[int,
                                                               str]) -> bool:
    return int(n.depth) - 1 in c


def callstack_set_curr_node(n: cfg_load.CalltreeCallsite, name: str,
                            c: Dict[int, str]) -> None:
    c[int(n.depth)] = name


def get_node_coverage_hitcount(demangled_name: str, callstack: Dict[int, str],
                               node: cfg_load.CalltreeCallsite,
                               profile: fuzzer_profile.FuzzerProfile,
                               is_first: bool) -> int:
    """Extracts the runtime coverage hitcount of a node in the calltree"""
    if profile.coverage is None:
        return -1

    node_hitcount: int = 0
    if is_first:
        # As this is the first node ensure it is indeed the entrypoint.
        # The difference is this node has node "parent" or prior nodes.

        if not profile.func_is_entrypoint(demangled_name):
            raise AnalysisError(
                "First node in calltree is non-fuzzer function")
        if profile.coverage.get_type() == 'kernel':
            # For now, assume EP is hit. TODO(David) adjust this.
            return 100

        coverage_data = profile.coverage.get_hit_details(demangled_name)

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
        logger.debug(f"Getting hit details {node.dst_function_name} -- "
                     f"{node.cov_ct_idx} -- {node.src_linenumber}")

        if profile.target_lang == "c-cpp":
            if profile.coverage.get_type() == 'kernel':
                # Handle coverage
                return profile.coverage.get_kernel_hitcount(node)
            else:
                coverage_data = profile.coverage.get_hit_details(
                    callstack_get_parent(node, callstack))
                for (n_line_number, hit_count_cov) in coverage_data:
                    logger.debug("  - iterating %d : %d", n_line_number,
                                 hit_count_cov)
                    if n_line_number == node.src_linenumber and hit_count_cov > 0:
                        node_hitcount = hit_count_cov
        elif profile.target_lang == "python":
            ih = profile.coverage.is_file_lineno_hit(
                callstack_get_parent(node, callstack), node.src_linenumber,
                True)
            if ih:
                node_hitcount = 200
        elif profile.target_lang == "jvm":
            coverage_data = profile.coverage.get_hit_details(
                callstack_get_parent(node, callstack))
            for (n_line_number, hit_count_cov) in coverage_data:
                logger.debug("  - iterating %d : %d", n_line_number,
                             hit_count_cov)
                if n_line_number == node.src_linenumber and hit_count_cov > 0:
                    node_hitcount = hit_count_cov
        elif profile.target_lang == "rust":
            coverage_data = profile.coverage.get_hit_details(
                callstack_get_parent(node, callstack))
            for (n_line_number, hit_count_cov) in coverage_data:
                logger.debug("  - iterating %d : %d", n_line_number,
                             hit_count_cov)
                if n_line_number == node.src_linenumber and hit_count_cov > 0:
                    node_hitcount = hit_count_cov
        node.cov_parent = callstack_get_parent(node, callstack)
    else:
        logger.error(
            "A node should either be the first or it must have a parent")
        raise AnalysisError(
            "A node should either be the first or it must have a parent")

    return node_hitcount


def get_hit_count_color(hit_count: int) -> str:
    """Map hitcount to color of target"""
    for cmin, cmax, cname, _ in constants.COLOR_CONSTANTS:
        if hit_count >= cmin and hit_count < cmax:
            return cname
    return "red"


def get_url_to_cov_report(profile, node, target_coverage_url):
    """ Get URL to coverage report for the node. """
    dst_options = [
        node.dst_function_name,
        utils.demangle_cpp_func(node.dst_function_name),
        utils.demangle_rust_func(node.dst_function_name),
        utils.demangle_jvm_func(node.dst_function_source_file,
                                node.dst_function_name)
    ]
    for dst in dst_options:
        try:
            fd = profile.dst_to_fd_cache[dst]
            return profile.resolve_coverage_link(target_coverage_url,
                                                 fd.function_source_file,
                                                 fd.function_linenumber,
                                                 fd.function_name)
        except KeyError:
            pass

        try:
            fd = profile.dst_to_fd_cache[utils.normalise_str(dst)]
            return profile.resolve_coverage_link(target_coverage_url,
                                                 fd.function_source_file,
                                                 fd.function_linenumber,
                                                 fd.function_name)
        except KeyError:
            pass

    return "#"


def get_parent_callsite_link(node, callstack, profile, target_coverage_url):
    """Gets the coverage callsite link of a given node."""
    if callstack_has_parent(node, callstack):
        parent_fname = callstack_get_parent(node, callstack)
        dst_options = [
            parent_fname,
            utils.demangle_cpp_func(parent_fname),
            utils.demangle_rust_func(parent_fname),
        ]
        for dst in dst_options:
            # First try the cache
            try:
                fd = profile.dst_to_fd_cache[dst]
                callsite_link = profile.resolve_coverage_link(
                    target_coverage_url, fd.function_source_file,
                    node.src_linenumber, fd.function_name)
                return callsite_link
            except KeyError:
                pass

            try:
                fd = profile.dst_to_fd_cache[utils.normalise_str(dst)]
                callsite_link = profile.resolve_coverage_link(
                    target_coverage_url, fd.function_source_file,
                    node.src_linenumber, fd.function_name)
                return callsite_link
            except KeyError:
                pass
    return "#"


def overlay_calltree_with_coverage(
        profile: fuzzer_profile.FuzzerProfile,
        proj_profile: project_profile.MergedProjectProfile, coverage_url: str,
        basefolder: str) -> None:
    # We use the callstack to keep track of all function parents. We need this
    # when looking up if a callsite was hit or not. This is because the coverage
    # information about a callsite is located in coverage data of the function
    # in which the callsite is placed.
    callstack: Dict[int, str] = dict()

    if profile.coverage is None:
        return

    is_first = True
    ct_idx = 0
    if profile.fuzzer_callsite_calltree is None:
        return

    target_name = profile.identifier
    target_coverage_url = utils.get_target_coverage_url(
        coverage_url, target_name, profile.target_lang)
    logger.info("Using coverage url: %s", target_coverage_url)
    for node in cfg_load.extract_all_callsites(
            profile.fuzzer_callsite_calltree):
        node.cov_ct_idx = ct_idx
        ct_idx += 1

        if profile.target_lang == "jvm":
            demangled_name = utils.demangle_jvm_func(
                node.dst_function_source_file, node.dst_function_name)
        elif profile.target_lang == "rust":
            demangled_name = utils.demangle_rust_func(node.dst_function_name)
        else:
            demangled_name = utils.demangle_cpp_func(node.dst_function_name)

        # Add to callstack
        callstack_set_curr_node(node, demangled_name, callstack)

        logger.debug("Checking callsite: %s", demangled_name)

        # Get hitcount for this node
        node.cov_hitcount = get_node_coverage_hitcount(demangled_name,
                                                       callstack, node,
                                                       profile, is_first)
        is_first = False

        node.cov_color = get_hit_count_color(node.cov_hitcount)
        node.cov_link = get_url_to_cov_report(profile, node,
                                              target_coverage_url)
        node.cov_callsite_link = get_parent_callsite_link(
            node, callstack, profile, target_coverage_url)
    # For python, do a hack where we check if any node is covered, and, if so,
    # ensure the entrypoint is covered.
    logger.info("Overlaying 2")
    all_nodes = cfg_load.extract_all_callsites(
        profile.fuzzer_callsite_calltree)
    if len(all_nodes) > 0:
        for node in cfg_load.extract_all_callsites(
                profile.fuzzer_callsite_calltree)[1:]:
            if node.cov_hitcount > 0:
                all_nodes[0].cov_hitcount = 200
                all_nodes[0].cov_color = get_hit_count_color(200)
                break

    # Extract data about which nodes unlocks data
    logger.info("Overlaying 3")
    all_callsites = cfg_load.extract_all_callsites(
        profile.fuzzer_callsite_calltree)
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

            try:
                fd = proj_profile.dst_to_fd_cache[n2.dst_function_name]
                if fd.total_cyclomatic_complexity > largest_blocked_count:
                    largest_blocked_count = fd.total_cyclomatic_complexity
                    largest_blocked_name = n2.dst_function_name
            except KeyError:
                pass

            forward_red += 1
            idx2 += 1
        prev_end = idx2 - 1
        # logger.info("Assigning forward red: %d for index %d"%(forward_red, idx1))
        n1.cov_forward_reds = forward_red
        n1.cov_largest_blocked_func = largest_blocked_name

    logger.info("Updating branch complexities")
    update_branch_complexities(proj_profile.all_functions, profile.coverage)
    profile.branch_blockers = detect_branch_level_blockers(
        proj_profile.all_functions, profile, target_coverage_url)
    logger.info("[+] found %d branch blockers.", len(profile.branch_blockers))
    branch_blockers_list = []
    for blk in profile.branch_blockers:
        branch_blockers_list.append({
            'blocked_side':
            repr(blk.blocked_side),
            'blocked_unique_not_covered_complexity':
            blk.blocked_unique_not_covered_complexity,
            'blocked_unique_reachable_complexity':
            blk.blocked_unique_reachable_complexity,
            'blocked_unique_functions':
            blk.blocked_unique_funcs,
            'blocked_not_covered_complexity':
            blk.blocked_not_covered_complexity,
            'blocked_reachable_complexity':
            blk.blocked_reachable_complexity,
            'sides_hitcount_diff':
            blk.sides_hitcount_diff,
            'source_file':
            blk.source_file,
            'branch_line_number':
            blk.branch_line_number,
            'blocked_side_line_numder':
            blk.blocked_side_line_numder,
            'function_name':
            blk.function_name
        })

    json_report.add_branch_blocker_key_value_to_report(profile.identifier,
                                                       'branch_blockers',
                                                       branch_blockers_list)


def update_branch_complexities(
        all_functions: Dict[str, function_profile.FunctionProfile],
        coverage: code_coverage.CoverageProfile) -> None:
    """
    Traverse every branch profile and update the side complexities based on reached funcs
    complexity.
    """
    for func in all_functions.values():
        for branch in func.branch_profiles.values():
            sides_number = len(branch.sides)
            for side_idx in range(sides_number):
                branch.sides[side_idx].unique_not_covered_complexity = 0
                branch.sides[side_idx].unique_reachable_complexity = 0
                branch.sides[side_idx].reachable_complexity = 0
                branch.sides[side_idx].not_covered_complexity = 0
                side_unique_funcs = branch.get_side_unique_reachable_funcnames(
                    side_idx)

                # Iterate over the list of funcs instead of set, because we want to account
                # for the complexity of repeating functions.
                for fn in branch.sides[side_idx].funcs:
                    if fn not in all_functions:
                        continue
                    new_comp = all_functions[fn].total_cyclomatic_complexity
                    branch.sides[side_idx].reachable_complexity += new_comp
                    if fn in side_unique_funcs:
                        branch.sides[
                            side_idx].unique_reachable_complexity += new_comp
                    if coverage.is_func_hit(fn) is False:
                        branch.sides[
                            side_idx].not_covered_complexity += new_comp
                        if fn in side_unique_funcs:
                            branch.sides[
                                side_idx].unique_not_covered_complexity += new_comp


def detect_branch_level_blockers(
        functions_profile: Dict[str, function_profile.FunctionProfile],
        fuzz_profile: fuzzer_profile.FuzzerProfile,
        target_coverage_url: str) -> List[FuzzBranchBlocker]:
    fuzz_blockers = []

    if fuzz_profile.coverage is None:
        logger.error(
            f"No coverage for fuzzer {fuzz_profile.binary_executable}."
            "Skipping branch blocker detection.")
        return []
    coverage = fuzz_profile.coverage

    for branch_string in coverage.branch_cov_map:
        blocked_side = None
        branch_hitcount = -1
        sides_hitcount = coverage.branch_cov_map[branch_string]
        if len(sides_hitcount) > 2:
            logger.debug(
                f'SPECIAL: switch statement {branch_string} {sides_hitcount}')
            # The first two elements are associated with the switch statement
            # line coverage. Here to update sides_hitcount and set branch_hitcount.
            branch_hitcount = max(sides_hitcount[:2])
            sides_hitcount = sides_hitcount[2:]

        # Catch exceptions in case some of the string splitting fails
        try:
            function_name, rest_string = branch_string.rsplit(':', maxsplit=1)
            line_number, column_number = rest_string.split(',')
        except ValueError:
            logger.debug(
                "branch-profiling: error getting function name from %s",
                branch_string)
            continue

        if function_name not in functions_profile:
            logger.debug(
                "branch-profiling: func name not in functions_profile %s",
                function_name)
            continue

        llvm_branch_profile = functions_profile[function_name].branch_profiles
        source_file_path = functions_profile[
            function_name].function_source_file
        # Just extract the file name and skip the path
        source_file_name = os.path.basename(source_file_path)
        llvm_branch_string = f'{source_file_name}:{line_number},{column_number}'

        if llvm_branch_string not in llvm_branch_profile:
            # TODO: there are cases that the column number of the branch is not consistent between
            # llvm and coverage debug info. For now we skip those cases.
            logger.debug("branch-profiling: failed to find branch profile %s",
                         llvm_branch_string)
            continue

        llvm_branch = llvm_branch_profile[llvm_branch_string]
        # For now this checks for not-taken branch sides, instead
        # it may become interesting to report less-taken side: like
        # the side that is taken less than 20% of the times
        taken_sides = []
        not_taken_sides = []
        for idx, sh in enumerate(sides_hitcount):
            if sh == 0:
                not_taken_sides.append(idx)
            else:
                taken_sides.append(idx)

        if len(taken_sides) == 0 or len(not_taken_sides) == 0:
            continue

        # Sanity checks for capturing any potential inconsistancy between coverage and LLVM.
        if len(sides_hitcount) != len(llvm_branch.sides):
            logger.debug(
                "Branch-blocker: inconsistent data found between COV vs LLVM:\n%s %s",
                llvm_branch_string, branch_string)
            logger.debug("llvm_branch.sides: %s", str(llvm_branch.sides))
            logger.debug("blocked_idx: %s", sides_hitcount)
            continue
        # We have some sides taken and some not taken sides => there are blockers.
        for blocked_idx in not_taken_sides:
            blocked_side = blocked_idx
            blocked_unique_not_covered_com = (
                llvm_branch.sides[blocked_idx].unique_not_covered_complexity)
            blocked_unique_reachable_com = (
                llvm_branch.sides[blocked_idx].unique_reachable_complexity)
            blocked_reachable_com = llvm_branch.sides[
                blocked_idx].reachable_complexity
            blocked_not_covered_com = llvm_branch.sides[
                blocked_idx].not_covered_complexity
            side_line = llvm_branch.sides[blocked_idx].pos
            side_line_number = side_line.split(':')[1].split(',')[0]
            blocked_unique_funcs = list(
                llvm_branch.get_side_unique_reachable_funcnames(blocked_idx))

            # Sanity check on line numbers: anomaly can happen because of debug info inaccuracy
            if int(line_number) > int(side_line_number):
                logger.debug(
                    "Branch-blocker: Anomalous branch sides line nubmers: %s:%s -> %s",
                    source_file_path, line_number, side_line_number)
                continue

            # Sanity check for fall through cases: checks if the branch side has coverage or not
            if coverage.get_type() == "file":
                if coverage.is_file_lineno_hit(source_file_path,
                                               int(side_line_number)):
                    logger.debug(
                        "Branch-blocker: fall through branch side is not blocked: %s",
                        side_line)
                    continue
            else:
                if coverage.is_func_lineno_hit(function_name,
                                               int(side_line_number)):
                    logger.debug(
                        "Branch-blocker: fall through branch side is not blocked: %s",
                        side_line)
                    continue

            hitcount_diff = max(sides_hitcount + [branch_hitcount])
            link = fuzz_profile.resolve_coverage_link(target_coverage_url,
                                                      source_file_path,
                                                      int(line_number),
                                                      function_name)
            new_blk = FuzzBranchBlocker(
                blocked_side, blocked_unique_not_covered_com,
                blocked_unique_reachable_com, blocked_unique_funcs,
                blocked_not_covered_com, blocked_reachable_com, hitcount_diff,
                source_file_path, line_number, side_line_number, function_name,
                link)
            fuzz_blockers.append(new_blk)

    fuzz_blockers.sort(
        reverse=True,
        key=lambda x: [
            x.blocked_unique_not_covered_complexity, x.
            blocked_unique_reachable_complexity, x.
            blocked_not_covered_complexity, x.blocked_reachable_complexity
        ])

    return fuzz_blockers


def extract_namespace(mangled_function_name, return_type=None):
    # logger.info("Demangling: %s" % (mangled_function_name))
    demangled_func_name = utils.demangle_rust_func(
        utils.demangle_cpp_func(mangled_function_name))
    # logger.info("Demangled name: %s" % (demangled_func_name))
    if return_type is not None and demangled_func_name.startswith(
            f"{return_type} "):
        demangled_func_name = demangled_func_name[len(return_type) + 1:]
        # logger.info("Removed function type: %s" % (demangled_func_name))
    if "::" not in demangled_func_name:
        return []

    split_namespace = demangled_func_name.split("::")
    name_spaces = []
    for elem in split_namespace:
        if len(elem) > 0:
            # Check: (anonymous namespace)
            if elem[0] == '(':
                name_spaces.append(elem)
            elif '(' in elem:
                name_spaces.append(elem.split("(")[0])
                break
            else:
                name_spaces.append(elem)

    # logger.info("split namespace: %s" % (str(name_spaces)))
    return name_spaces


def convert_debug_info_to_signature_v2(function, introspector_func):
    function['return_type'] = 'N/A'
    function['args'] = []
    try:
        return_type = convert_param_list_to_str_v2(
            function['func_signature_elems']['return_type'])
        function['return_type'] = return_type
        func_signature = return_type + " "
    except KeyError:
        return 'N/A'

    # Assess if there is a namespace and if we have more args than what there
    # should be, e.g. if this is a method on an object. We need to identify
    # this because we want the function signature to be equal to what developers
    # see.

    # First step: Identify namespae
    # 1) demangle raw name
    # 2) identify namespace
    # 3) identify if namespace last part matches first argument
    # 4) assemble
    namespace = extract_namespace(introspector_func['raw-function-name'],
                                  return_type)

    func_name = ''
    param_idx = 0
    # Is this a class function?
    if len(function['func_signature_elems']['params']) > 0:
        if len(namespace) > 1:
            # Constructor handling
            if namespace[-1] == convert_param_list_to_str_v2(
                    function['func_signature_elems']['params'][0]).replace(
                        " *", ""):
                func_name = "::".join(namespace[0:-1]) + "::"
                param_idx += 1
            # Destructor handling
            elif "~" in namespace[-1] and namespace[-1].replace(
                    "~", "") == convert_param_list_to_str_v2(
                        function['func_signature_elems']['params'][0]).replace(
                            " *", ""):
                func_name = "::".join(namespace[0:-1]) + "::"

                if not convert_param_list_to_str_v2(
                        function['func_signature_elems']['params'][0]) == '~':
                    function['name'] = '~' + function['name']
                param_idx += 1
            # Class object handling
            elif namespace[-2] == convert_param_list_to_str_v2(
                    function['func_signature_elems']['params'][0]).replace(
                        " *", "").replace("const ", ""):
                func_name = "::".join(namespace[0:-1]) + "::"
                param_idx += 1
            else:
                # Simple function in namespace but not in a class
                # No increasae in param_idx, since we don't eat the object
                # instance pointer.
                func_name = "::".join(namespace[0:-1]) + "::"
    func_name += function['name']

    func_signature += func_name
    func_signature += '('
    for idx in range(param_idx,
                     len(function['func_signature_elems']['params'])):
        param_string = convert_param_list_to_str_v2(
            function['func_signature_elems']['params'][idx])
        function['args'].append(param_string)
        func_signature += param_string
        if idx < len(function['func_signature_elems']['params']) - 1:
            func_signature += ', '
    func_signature += ')'
    return func_signature


def convert_param_list_to_str_v2(param_list):
    pre = ""
    med = ""
    post = ""
    is_struct = False
    for param in param_list:
        if param == "DW_TAG_pointer_type":
            post += "*"
        elif param == 'DW_TAG_reference_type':
            post += '&'
        elif param == 'DW_TAG_structure_type':
            is_struct = True
        elif param == "DW_TAG_base_type":
            continue
        elif param == "DW_TAG_typedef":
            continue
        elif param == 'DW_TAG_class_type':
            continue
        elif param == "DW_TAG_const_type":
            pre += "const "
        else:
            med += param
            if is_struct:
                med = 'struct ' + med

    raw_sig = pre.strip() + " " + med + " " + post
    return raw_sig.strip()


def correlate_introspector_func_to_debug_information(if_func,
                                                     all_debug_functions,
                                                     debug_dict_by_name,
                                                     debug_dict_by_filename):
    """Correlate a single LLVM-based function to a given function in the
    collected debug information."""
    # Check if name matches. If so, this one is easy.
    same_name_dfs = debug_dict_by_name.get(if_func['Func name'], [])

    for debug_function in same_name_dfs:
        if debug_function.get('name', '') == if_func['Func name']:
            func_signature = convert_debug_info_to_signature_v2(
                debug_function, if_func)
            return func_signature, debug_function

    # We could not find the right one, let's search more broadly for it.
    target_minimum = 999999
    tfunc_signature = None
    most_likely_func = None

    for dfunction in debug_dict_by_filename.get(
            os.path.normpath(if_func['Functions filename']), []):
        try:
            dline = int(dfunction['source'].get('source_line', '-1'))
        except ValueError:
            continue

        if dfunction['source'].get('source_file', '') == os.path.normpath(
                if_func['Functions filename']):

            # Match based on containment, as there can be discrepancies between function
            # signatur start (as from frunc_to_match) and the lines of code of the first
            # instruction.
            distance_between_beginnings = int(
                if_func['source_line_begin']) - dline

            if distance_between_beginnings == 0 and dline != 0:
                func_signature = convert_debug_info_to_signature_v2(
                    dfunction, if_func)
                return func_signature, dfunction

            elif distance_between_beginnings > 0 and distance_between_beginnings < target_minimum:
                tfunc_signature = convert_debug_info_to_signature_v2(
                    dfunction, if_func)
                most_likely_func = dfunction
                target_minimum = distance_between_beginnings

    if most_likely_func is not None:
        return tfunc_signature, most_likely_func

    # Could not find the relevant stuff
    return None, None


def correlate_introspection_functions_to_debug_info(all_functions_json_report,
                                                    debug_all_functions,
                                                    proj_lang,
                                                    report_dict=None):
    """Correlates function data collected by debug information to function
    data collected by LLVMs module, and uses the correlated data to generate
    function signatures for each function based on debug information."""
    if not report_dict:
        report_dict = {}

    # Find header files
    normalized_paths = set()
    for header_file in report_dict.get('all_files_in_project', []):
        normalized_paths.add(os.path.normpath(header_file['source_file']))

    # A lot of look-ups are needed when matching LLVM functions to debug
    # functions. Start with creating two indexes to make these look-ups
    # faster.
    debug_dict_by_name = dict()
    debug_dict_by_filename = dict()
    for df in debug_all_functions:
        # Normalize the source file
        df['source']['source_file'] = os.path.normpath(df['source'].get(
            'source_file', ''))

        # Find the header file of this debug function.
        possible_header_files = set()
        for header_src_file in normalized_paths:
            if not (header_src_file.endswith(".h")
                    or header_src_file.endswith(".hpp")):
                continue
            if not os.path.isfile(header_src_file):
                continue
            try:
                with open(header_src_file, 'r') as header_file_fd:
                    content = header_file_fd.read()
            except UnicodeDecodeError:
                content = ""

            name = df.get('name', 'TOTALLYRANDOMNOTFUNCNAME123')
            for line_idx, line in enumerate(content.split("\n")):
                if f'{name}(' in line:
                    possible_header_files.add(header_src_file)
        df['possible-header-files'] = list(possible_header_files)

        # Append debug function to name-index.
        entry_list1 = debug_dict_by_name.get(df.get('name', ''), [])
        entry_list1.append(df)
        debug_dict_by_name[df.get('name', '')] = entry_list1

        # Append debug function to file-index.
        entry_list2 = debug_dict_by_filename.get(
            df['source'].get('source_file', ''), [])
        entry_list2.append(df)
        debug_dict_by_filename[df['source'].get('source_file',
                                                '')] = entry_list2

    for dl3 in debug_dict_by_filename:
        print("%s ------- %d" % (dl3, len(debug_dict_by_filename[dl3])))

    # Now correlate signatures
    for if_func in all_functions_json_report:
        func_sig, correlated_debug_function = correlate_introspector_func_to_debug_information(
            if_func, debug_all_functions, debug_dict_by_name,
            debug_dict_by_filename)

        if func_sig is not None:
            if_func['function_signature'] = func_sig
            if_func['debug_function_info'] = correlated_debug_function
        else:
            if proj_lang == 'jvm':
                if_func['function_signature'] = if_func['Func name']
            else:
                if_func['function_signature'] = 'N/A'
            if_func['debug_function_info'] = dict()


def extract_all_sources(language):
    all_files = set()
    for root, dirs, files in os.walk('/src/'):
        for f in files:
            all_files.add(os.path.join(root, f))
    interesting_source_files = set()

    if language == 'jvm':
        test_extensions = ['.java', '.scala', '.sc', '.groovy', '.kt', '.kts']
    elif language == 'python':
        test_extensions = ['.py']
    elif language == 'rust':
        test_extensions = ['.rs']
    else:
        test_extensions = ['.cc', '.cpp', '.cxx', '.c++', '.c', '.h', '.hpp']

    to_avoid = [
        'fuzztest', 'aflplusplus', 'libfuzzer', 'googletest', 'thirdparty',
        'third_party', '/build/', '/usr/local/', '/fuzz-introspector/',
        '/root/.cache/', 'honggfuzz', '/src/inspector/', '/src/.venv'
    ]

    for file in all_files:
        if not any(file.endswith(ext) for ext in test_extensions):
            continue

        # Absolute path
        if any([avoid in file for avoid in to_avoid]):
            continue
        if file.startswith('/src/source-code'):
            continue
        if file.startswith('/src/inspector/'):
            continue

        interesting_source_files.add(file)
    return interesting_source_files


def extract_test_information(report_dict=None, language='c-cpp'):
    """Extract test information for different project language."""
    if not report_dict:
        report_dict = {}
    if language == 'c-cpp':
        return _extract_test_information_cpp(report_dict)
    elif language == 'jvm':
        return _extract_test_information_jvm()
    else:
        # Currently only support c-cpp or jvm project
        return set()


def _extract_test_information_cpp(report_dict):
    """Correlates function data collected by debug information to function
    data collected by LLVMs module, and uses the correlated data to generate
    function signatures for each function based on debug information."""

    # Find header files
    normalized_paths = set()
    for header_file in report_dict.get('all_files_in_project', []):
        normalized_paths.add(os.path.normpath(header_file['source_file']))

    directories = set()

    # All directories added
    for path in normalized_paths:
        if path.startswith('/usr/'):
            continue
        directories.add('/'.join(path.split('/')[:-1]))
    return extract_tests_from_directories(directories, 'c-cpp')


def extract_tests_from_directories(directories, language) -> Set[str]:
    """Extracts test files from a given collection of directory paths and also
    copies them to the `constants.SAVED_SOURCE_FOLDER` folder with the same
    absolute path appended."""
    all_files_in_subtree = set()
    for directory in directories:
        for root, _, files in os.walk(directory):
            for f in files:
                all_files_in_subtree.add(os.path.join(root, f))

    all_directories = set()
    for file in all_files_in_subtree:
        assembled_dir = '/'
        for dd2 in file.split('/'):
            assembled_dir += dd2
            if os.path.isdir(assembled_dir):
                all_directories.add(assembled_dir)
            assembled_dir += '/'

    inspirations = ["sample", "test", "example"]
    all_inspiration_dirs = set()
    for directory in all_directories:
        if any(ins in directory for ins in inspirations):
            all_inspiration_dirs.add(directory)

    if language == 'jvm':
        # Get all jvm source files
        test_extensions = ['.java', '.scala', '.sc', '.groovy', '.kt', '.kts']
    elif language == 'python':
        # Get all python source files
        test_extensions = ['.py']
    elif language == 'rust':
        # Get all rust source files
        test_extensions = ['.rs']
    else:
        # Get all c/cpp source files
        test_extensions = ['.cc', '.cpp', '.cxx', '.c++', '.c']

    all_test_files = set()
    to_avoid = [
        'fuzztest', 'aflplusplus', 'libfuzzer', 'googletest', 'thirdparty',
        'third_party', '/build/', '/usr/local/', '/fuzz-introspector/',
        '/root/.cache/', '/usr/'
    ]
    for directory in all_inspiration_dirs:
        for root, dirs, files in os.walk(directory):
            for f in files:
                if not any(f.endswith(ext) for ext in test_extensions):
                    continue
                # Absolute path
                absolute_path = os.path.join(root, f)
                if any([avoid in absolute_path for avoid in to_avoid]):
                    continue
                if absolute_path.startswith('/out/'):
                    continue
                if absolute_path.startswith('/src/inspector/'):
                    continue
                try:
                    with open(absolute_path, 'r') as file_fp:
                        if 'LLVMFuzzerTestOneInput' in file_fp.read():
                            continue
                        # For rust projects
                        if 'fuzz_target' in file_fp.read():
                            continue
                        # For python projects
                        if '.Fuzz()' in file_fp.read():
                            continue
                        # For jvm projects
                        if 'fuzzerTestOneInput' in file_fp.read():
                            continue
                except UnicodeDecodeError:
                    continue
                all_test_files.add(absolute_path)

    # Iterate through all directories and search for files with test in them.
    for directory in all_directories:
        for root, dirs, files in os.walk(directory):
            for f in files:
                if not any(f.endswith(ext) for ext in test_extensions):
                    continue
                # Absolute path
                absolute_path = os.path.join(root, f)
                if any([avoid in absolute_path for avoid in to_avoid]):
                    continue
                if absolute_path.startswith('/out/'):
                    continue
                if absolute_path.startswith('/src/inspector/'):
                    continue
                if absolute_path.startswith('/usr/'):
                    continue
                if "test" in f:
                    all_test_files.add(absolute_path)
    new_test_files = set()
    for test_file in all_test_files:
        if test_file.startswith('//'):
            test_file = test_file[1:]
        new_test_files.add(test_file)
    all_test_files = new_test_files

    logger.info("All test files")
    for test_file in all_test_files:
        logger.info(test_file)
        dst = constants.SAVED_SOURCE_FOLDER + '/' + test_file
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copy(test_file, dst)

    return all_test_files


def _extract_test_information_jvm():
    """Search the /src directory for source code of the JVM project and
    locate all java files in the subdirectories. Include all the Java source
    files in the default test package location src/test/java packages which is
    common for different Java build system. Then analyse the remaining source
    code to locate extra example source files."""

    all_test_files = set()
    source_code_extensions = ('.java', '.scala', '.sc', '.kt', '.kts',
                              '.groovy')
    inspirations = ['sample', 'example', 'documentation', 'demo']

    # Java project source code is meant to exist in the $SRC directory
    base_dir = os.path.abspath(os.environ.get('SRC', '/src'))

    # Walk through all directories under $SRC and locate all standard directories
    # of /src/main/java and /src/test/java for Java source and test files. Also
    # locate sample or example directories under $SRC for additional search
    source_paths = set()
    test_paths = set()
    sample_paths = set()
    for root, _, _ in os.walk(base_dir):
        if root.endswith('src/main/java'):
            source_paths.add(root)
        if root.endswith('src/test/java'):
            test_paths.add(root)
        if any(inspiration in root for inspiration in inspirations):
            sample_paths.add(root)

    # Walk through all the packages under test paths and include the test files
    for test_path in test_paths:
        for root, _, files in os.walk(test_path):
            for file in files:
                if file.endswith(source_code_extensions):
                    path = os.path.join(root,
                                        file).replace(f'{test_path}/', '')
                    all_test_files.add(path)

    # Walk through all the packages under source paths and locate example sources
    for source_path in source_paths:
        for root, _, files in os.walk(source_path):
            for file in files:
                if file.endswith(source_code_extensions) and any(
                        inspiration in file for inspiration in inspirations):
                    path = os.path.join(root,
                                        file).replace(f'{source_path}/', '')
                    all_test_files.add(path)

    # Walk through all the files under possible sample path and locate example sources
    for sample_path in sample_paths:
        for root, _, files in os.walk(sample_path):
            for file in files:
                if file.endswith(source_code_extensions):
                    path = os.path.join(root,
                                        file).replace(f'{sample_path}/', '')
                    all_test_files.add(path)

    return all_test_files


def light_correlate_source_to_executable(language):
    """Extracts pairs of harness source/executable"""
    if language == 'jvm' or language == 'python':
        # Skip this step for jvm or python projects
        return []

    out_dir = os.getenv('OUT', '/out/')
    textcov_dir = os.path.join(out_dir, 'textcov_reports')

    if not os.path.isdir(textcov_dir):
        return []

    cov_reports = []
    for cov_report in os.listdir(textcov_dir):
        if cov_report.endswith('.covreport'):
            cov_reports.append(os.path.join(textcov_dir, cov_report))
    for cov_report in cov_reports:
        print('- cov report: %s' % (cov_report))

    all_source_files = extract_all_sources(language)
    pairs = []
    # Match based on file names. This should be the most primitive but
    # will catch a large number of targets
    for source_file in all_source_files:
        harness_source_file = os.path.splitext(
            os.path.basename(source_file))[0]
        matches = set()
        for cov_report in cov_reports:
            cov_report_base = os.path.splitext(os.path.basename(cov_report))[0]
            if cov_report_base == harness_source_file:
                matches.add(cov_report_base)
        if len(matches) == 1:
            pairs.append({
                'harness_source': source_file,
                'harness_executable': matches.pop()
            })

    return pairs
