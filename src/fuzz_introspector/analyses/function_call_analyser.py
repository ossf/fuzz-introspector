# Copyright 2022 Fuzz Introspector Authors
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
"""Analysis plugin for introspection sinks of interest"""

import logging

from typing import (
    List,
    Tuple,
    Dict
)

from fuzz_introspector import analysis
from fuzz_introspector import cfg_load
from fuzz_introspector import html_helpers
from fuzz_introspector import utils
from fuzz_introspector.datatypes import (
    project_profile,
    fuzzer_profile,
    function_profile
)

logger = logging.getLogger(name=__name__)


class Analysis(analysis.AnalysisInterface):
    """This Analysis aims to analyse and generate html report content table
    to show all occurence of third party function call within the target
    project and if those calls are statically reached or dynamically covered.
    """

    def __init__(self) -> None:
        pass

    @staticmethod
    def get_name():
        return "ThirdPartyAPICoverageAnalyser"

    def get_source_file(self, callsite) -> str:
        """This function aims to dig up the callsitecalltree of a function
        call and get its source file path.
        """
        src_file = callsite.src_function_source_file
        if not src_file:
            parent = callsite.parent_calltree_callsite
            if parent:
                src_file = parent.dst_function_source_file
                src_file = src_file if src_file else ""

        return src_file

    def get_parent_func_name(self, callsite) -> str:
        """This function aims to dig up the callsitecalltree of a function
        call and get its parent function name.
        """
        func_file = callsite.src_function_source_file
        if not func_file:
            parent = callsite.parent_calltree_callsite
            if parent:
                func_file = parent.dst_function_name
                func_file = func_file if func_file else ""

        return func_file

    def add_callsite_record(
        self,
        target_func_list: List[str],
        func_name: str,
        source_file_list: List[str],
        callsites: Dict[str, List[str]]
    ) -> List[str]:
        """This function aims to add all third party function call to its
        source location and line number mapping to a combined dictionary.
        """
        exist_list = []
        if func_name in target_func_list:
            if func_name in callsites.keys():
                func_list = callsites[func_name]
            else:
                func_list = []
            for item in source_file_list:
                if item not in func_list:
                    func_list.append(item)
                else:
                    exist_list.append(item)
            callsites.update({func_name: func_list})

        return exist_list

    def third_party_func_profile(
        self,
        profile: project_profile.MergedProjectProfile,
        callsites: List[cfg_load.CalltreeCallsite],
        function_list: List[function_profile.FunctionProfile]
    ) -> Tuple[
        List[function_profile.FunctionProfile],
        Dict[str, List[str]],
        List[str]
    ]:
        # Build up target function list
        target_list = [
            fd for fd in profile.all_functions.values() if not fd.function_source_file
        ]

        target_func_list = [
            func.function_name for func in target_list
        ]

        # Add unreachable target functions
        for function in function_list:
            if function.function_name not in target_func_list:
                if not function.function_source_file:
                    target_list.append(function)
                    target_func_list.append(function.function_name)

        # Create list of call site for each funcitons
        callsite_dict: Dict[str, List[str]] = dict()

        for callsite in callsites:
            func_name = callsite.dst_function_name
            src_file = self.get_source_file(callsite)
            parent_func = self.get_parent_func_name(callsite)
            src_file_with_line = "%s#%s:%s" % (
                src_file,
                parent_func,
                callsite.src_linenumber
            )
            self.add_callsite_record(
                target_func_list,
                func_name,
                [src_file_with_line],
                callsite_dict
            )

        # Discover reachable func calls
        reachable_func_list = []

        for function in function_list:
            for func_name in function.callsite.keys():

                reachable_func_list.extend(
                    self.add_callsite_record(
                        target_func_list,
                        func_name,
                        function.callsite[func_name],
                        callsite_dict
                    )
                )

        return target_list, callsite_dict, reachable_func_list

    def analysis_func(
        self,
        toc_list: List[Tuple[str, str, int]],
        tables: List[str],
        proj_profile: project_profile.MergedProjectProfile,
        profiles: List[fuzzer_profile.FuzzerProfile],
        basefolder: str,
        coverage_url: str,
        conclusions: List[html_helpers.HTMLConclusion]
    ) -> str:
        """
        Performs an analysis for all third party API call in the target project.
        Finds the set of third party API call in the project code and provide
        coverage information of each of their occurrent.
        1) Displays each occurring of the third party function call and its location
           in terms of source file and line number
        2) Shows if each of those third party function call location is statically
           reachable
        3) Analyse the fuzzer report to determine if each of those third party function
           call location is dynamically covered by any of the fuzzers, and also show the
           name of the fuzzers that covered that line of code.
        """
        logger.info(f" - Running analysis {Analysis.get_name()}")

        # Getting data
        callsite_list = []
        function_list = []
        for profile in profiles:
            callsite_list.extend(cfg_load.extract_all_callsites(profile.function_call_depths))
            for key in profile.all_class_functions.keys():
                function_list.append(profile.all_class_functions[key])
        (func_profile_list, called_func_dict, reachable_func_list) = (
            self.third_party_func_profile(proj_profile, callsite_list, function_list)
        )

        html_string = ""
        html_string += "<div class=\"report-box\">"

        html_string += html_helpers.html_add_header_with_link(
            "Function call coverage",
            1,
            toc_list
        )

        # Table with all function calls for each files
        html_string += "<div class=\"collapsible\">"
        html_string += (
            "<p>"
            "This section shows a list of 3rd party function "
            "calls and their relative coverage information. "
            "By static analysis of the target project code, "
            "all of the 3rd party function call and their caller "
            "information, including the source file and line "
            "number that initiate the call are captured. "
            "The caller source code file and line number are "
            "shown in column 2 while column 1 is the function "
            "name of the 3rd party function call. Each occurrent "
            "of the 3rd party function call will occuply "
            "a separate row. Column 3 of each row indicate if "
            "the 3rd party call in the source file line is "
            "unreachable. Column 4 lists all fuzzers that have "
            "covered that particular system call in "
            "that specific location (source file and line)"
            "during their dynamic fuzzing."
            "</p>"
        )

        html_string += html_helpers.html_add_header_with_link(
            "Function in each files in report",
            2,
            toc_list
        )

        # Third party function calls table
        tables.append(f"myTable{len(tables)}")
        html_string += html_helpers.html_create_table_head(
            tables[-1],
            [
                ("Target sink", ""),
                ("Callsite location",
                 "Source file, line number and parent function of this function call. "
                 "Based on static analysis."),
                ("Reached by fuzzer",
                 "Is this code reachable by any functions? "
                 "Based on static analysis."),
                ("Covered by Fuzzers",
                 "The specific list of fuzzers that cover this function call. "
                 "Based on dynamic analysis.")
            ]
        )

        # Loop through each function call exists in this project
        # Filer to only look for functions of interest
        command_injection_sinks = [
            "system",
            "execve",
            "execl",
            "wordexp",
            "popen",
            "fdopen"
        ]
        # Keeping memory unsafe sinks empty for now.
        # memory_unsafe_sinks = [
        #     "strcpy",
        #     "memcpy",
        # ]
        functions_of_interest = command_injection_sinks
        for fd in func_profile_list:
            func_name = utils.demangle_cpp_func(fd.function_name)

            if func_name not in functions_of_interest:
                continue

            # Retrieve called location as a list for this function
            if fd.function_name in called_func_dict.keys():
                called_location_list = called_func_dict[fd.function_name]
                if len(called_location_list) == 0:
                    called_location_list = [""]
            else:
                called_location_list = [""]

            # Loop through the list of calledlocation for this function
            for called_location in called_location_list:
                # Determine if the function call in this called location is reachable
                hit = "Yes" if (called_location in reachable_func_list) else "No"

                # Determine if this called location is covered by any fuzzers
                fuzzer_hit = False
                coverage = proj_profile.runtime_coverage
                for parent_func in fd.incoming_references:
                    try:
                        lineno = int(called_location.split(":")[1])
                    except ValueError:
                        continue
                    if coverage.is_func_lineno_hit(parent_func, lineno):
                        fuzzer_hit = True
                        break
                list_of_fuzzer_covered = fd.reached_by_fuzzers if fuzzer_hit else [""]

                html_string += html_helpers.html_table_add_row([
                    f"{func_name}",
                    f"{called_location}",
                    f"{hit}",
                    f"{str(list_of_fuzzer_covered)}"
                ])
        html_string += "</table>"

        html_string += "</div>"  # .collapsible
        html_string += "</div>"  # report-box
        return html_string
