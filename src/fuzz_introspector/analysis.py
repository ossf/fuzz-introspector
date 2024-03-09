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

from typing import (
    Dict,
    List,
    Type,
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
        self.profiles = data_loader.load_all_profiles(self.base_folder,
                                                      self.language,
                                                      parallelise)
        """Generates the `proj_profile` and `profiles` elements of this class
        based on the raw data given as arguments. This function must be called
        before any real use of `IntrospectionProject` can happen.
        """
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
                args=(profile, self.base_folder, return_dict,
                      "uniq-%s" % (idx), semaphore))
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
        pass

    @classmethod
    @abc.abstractmethod
    def get_name(cls):
        """Return name of analysis"""
        pass

    @abc.abstractmethod
    def get_json_string_result(self):
        """Return json_string_result"""
        pass

    @abc.abstractmethod
    def set_json_string_result(self, string):
        """Set json_string_result"""
        pass

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
            coverage_data = profile.coverage.get_hit_details(
                callstack_get_parent(node, callstack))
            for (n_line_number, hit_count_cov) in coverage_data:
                logger.debug(
                    f"  - iterating {n_line_number} : {hit_count_cov}")
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
                logger.debug(
                    f"  - iterating {n_line_number} : {hit_count_cov}")
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
    for cmin, cmax, cname, rgb in constants.COLOR_CONSTANTS:
        if hit_count >= cmin and hit_count < cmax:
            return cname
    return "red"


def get_url_to_cov_report(profile, node, target_coverage_url):
    """ Get URL to coverage report for the node. """
    dst_options = [
        node.dst_function_name,
        utils.demangle_cpp_func(node.dst_function_name),
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
        dst_options = [parent_fname, utils.demangle_cpp_func(parent_fname)]
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
    logger.info(f"Using coverage url: {target_coverage_url}")
    logger.info("Overlaying 1")
    for node in cfg_load.extract_all_callsites(
            profile.fuzzer_callsite_calltree):
        node.cov_ct_idx = ct_idx
        ct_idx += 1

        if profile.target_lang == "jvm":
            demangled_name = utils.demangle_jvm_func(
                node.dst_function_source_file, node.dst_function_name)
        else:
            demangled_name = utils.demangle_cpp_func(node.dst_function_name)

        # Add to callstack
        callstack_set_curr_node(node, demangled_name, callstack)

        logger.debug(f"Checking callsite: { demangled_name}")

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
    logger.info(f"[+] found {len(profile.branch_blockers)} branch blockers.")
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
    json_report.add_fuzzer_key_value_to_report(profile.identifier,
                                               'branch_blockers',
                                               branch_blockers_list)


def update_branch_complexities(
        all_functions: Dict[str, function_profile.FunctionProfile],
        coverage: code_coverage.CoverageProfile) -> None:
    """
    Traverse every branch profile and update the side complexities based on reached funcs
    complexity.
    """
    for func_k, func in all_functions.items():
        for branch_k, branch in func.branch_profiles.items():
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
                f"branch-profiling: error getting function name from {branch_string}"
            )
            continue

        if function_name not in functions_profile:
            logger.debug(
                f"branch-profiling: func name not in functions_profile {function_name}"
            )
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
            logger.debug(
                f"branch-profiling: failed to find branch profile {llvm_branch_string}"
            )
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
                "Branch-blocker: inconsistent data found between COV vs LLVM:\n%s %s"
                % (llvm_branch_string, branch_string))
            logger.debug("llvm_branch.sides: %s" % str(llvm_branch.sides))
            logger.debug("blocked_idx: %s" % sides_hitcount)
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
                    "Branch-blocker: Anomalous branch sides line nubmers: %s:%s -> %s"
                    % (source_file_path, line_number, side_line_number))
                continue

            # Sanity check for fall through cases: checks if the branch side has coverage or not
            if coverage.get_type() == "file":
                if coverage.is_file_lineno_hit(source_file_path,
                                               int(side_line_number)):
                    logger.debug(
                        "Branch-blocker: fall through branch side is not blocked: %s"
                        % (side_line))
                    continue
            else:
                if coverage.is_func_lineno_hit(function_name,
                                               int(side_line_number)):
                    logger.debug(
                        "Branch-blocker: fall through branch side is not blocked: %s"
                        % (side_line))
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
    demangled_func_name = utils.demangle_cpp_func(mangled_function_name)
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
    logger.info("Namespace: %s" % (str(namespace)))
    # Is this a class function?
    if len(function['func_signature_elems']['params']) > 0:
        if len(namespace) > 1:
            # Constructor handling
            if namespace[-1] == convert_param_list_to_str_v2(
                    function['func_signature_elems']['params'][0]).replace(
                        " *", ""):
                logger.info("Option 1")
                func_name = "::".join(namespace[0:-1]) + "::"
                param_idx += 1
            # Destructor handling
            elif "~" in namespace[-1] and namespace[-1].replace(
                    "~", "") == convert_param_list_to_str_v2(
                        function['func_signature_elems']['params'][0]).replace(
                            " *", ""):
                logger.info("Option 2")
                func_name = "::".join(namespace[0:-1]) + "::"

                if not convert_param_list_to_str_v2(
                        function['func_signature_elems']['params'][0]) == '~':
                    function['name'] = '~' + function['name']
                param_idx += 1
            # Class object handling
            elif namespace[-2] == convert_param_list_to_str_v2(
                    function['func_signature_elems']['params'][0]).replace(
                        " *", "").replace("const ", ""):
                logger.info("Option 3")
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
    for param in param_list:
        if param == "DW_TAG_pointer_type":
            post += "*"
        elif param == 'DW_TAG_reference_type':
            post += '&'
        elif param == 'DW_TAG_structure_type':
            continue
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
                                                    debug_all_functions):
    """Correlates function data collected by debug information to function
    data collected by LLVMs module, and uses the correlated data to generate
    function signatures for each function based on debug information."""

    # A lot of look-ups are needed when matching LLVM functions to debug
    # functions. Start with creating two indexes to make these look-ups
    # faster.
    debug_dict_by_name = dict()
    debug_dict_by_filename = dict()
    for df in debug_all_functions:
        # Normalize the source file
        df['source']['source_file'] = os.path.normpath(df['source'].get(
            'source_file', ''))

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

    for if_func in all_functions_json_report:
        func_sig, correlated_debug_function = correlate_introspector_func_to_debug_information(
            if_func, debug_all_functions, debug_dict_by_name,
            debug_dict_by_filename)

        if func_sig is not None:
            if_func['function_signature'] = func_sig
            if_func['debug_function_info'] = correlated_debug_function
        else:
            if_func['function_signature'] = 'N/A'
            if_func['debug_function_info'] = dict()
