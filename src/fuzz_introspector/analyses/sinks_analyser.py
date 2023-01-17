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

import json
import logging

from typing import (
    Any,
    List,
    Tuple,
    Dict
)

from fuzz_introspector import (
    analysis,
    code_coverage,
    cfg_load,
    html_helpers,
    json_report,
    utils
)

from fuzz_introspector.datatypes import (
    project_profile,
    fuzzer_profile,
    function_profile
)

logger = logging.getLogger(name=__name__)

# Common sink functions / methods for different language implementation
SINK_FUNCTION = {
    'c-cpp': [
        ('', 'system'),
        ('', 'execl'),
        ('', 'execlp'),
        ('', 'execle'),
        ('', 'execv'),
        ('', 'execvp'),
        ('', 'execve'),
        ('', 'wordexp'),
        ('', 'popen'),
        ('', 'fdopen')
    ],
    'python': [
        ('<builtin>', 'exec'),
        ('<builtin>', 'eval'),
        ('subprocess', 'call'),
        ('subprocess', 'run'),
        ('subprocess', 'Popen'),
        ('subprocess', 'check_output'),
        ('os', 'system'),
        ('os', 'popen'),
        ('os', 'spawnlpe'),
        ('os', 'spawnve'),
        ('os', 'exec'),
        ('os', 'execl'),
        ('os', 'execle'),
        ('os', 'execlp'),
        ('os', 'execlpe'),
        ('os', 'execv'),
        ('os', 'execve'),
        ('os', 'execvp'),
        ('os', 'execlpe'),
        ('asyncio', 'create_subprocess_shell'),
        ('asyncio', 'create_subprocess_exec'),
        ('asyncio', 'run'),
        ('asyncio', 'sleep'),
        ('logging.config', 'listen'),
        ('code.InteractiveInterpreter', 'runsource'),
        ('code.InteractiveInterpreter', 'runcode'),
        ('code.InteractiveInterpreter', 'write'),
        ('code.InteractiveConsole', 'push'),
        ('code.InteractiveConsole', 'interact'),
        ('code.InteractiveConsole', 'raw_input'),
        ('code', 'interact'),
        ('code', 'compile_command')
    ],
    'jvm': [
        ('java.lang.Runtime', 'exec'),
        ('javax.xml.xpath.XPath', 'compile'),
        ('javax.xml.xpath.XPath', 'evaluate'),
        ('java.lang.Thread', 'sleep'),
        ('java.lang.Thread', 'run'),
        ('java.lang.Runnable', 'run'),
        ('java.util.concurrent.Executor', 'execute'),
        ('java.util.concurrent.Callable', 'call'),
        ('java.lang.System', 'console'),
        ('java.lang.System', 'load'),
        ('java.lang.System', 'loadLibrary'),
        ('java.lang.System', 'apLibraryName'),
        ('java.lang.System', 'runFinalization'),
        ('java.lang.System', 'setErr'),
        ('java.lang.System', 'setIn'),
        ('java.lang.System', 'setOut'),
        ('java.lang.System', 'setProperties'),
        ('java.lang.System', 'setProperty'),
        ('java.lang.System', 'setSecurityManager'),
        ('java.lang.ProcessBuilder', 'directory'),
        ('java.lang.ProcessBuilder', 'inheritIO'),
        ('java.lang.ProcessBuilder', 'command'),
        ('java.lang.ProcessBuilder', 'redirectError'),
        ('java.lang.ProcessBuilder', 'redirectErrorStream'),
        ('java.lang.ProcessBuilder', 'redirectInput'),
        ('java.lang.ProcessBuilder', 'redirectOutput'),
        ('java.lang.ProcessBuilder', 'start')
    ]
}


class SinkCoverageAnalyser(analysis.AnalysisInterface):
    """This Analysis aims to analyse and generate html report content table
    to show all occurence of possible sink functions / methods existed in the
    target project and if those functions / methods are statically reached or
    dynamically covered by any of the fuzzers. If not, it also provides the
    closet callable entry points to those sink functions / methods for fuzzer
    developers to improve their fuzzers to statically reached and dynamically
    covered those sensitive sink fnctions / method in aid to discover possible
    code / command injection through though fuzzing on sink functions / methods..
    """
    name: str = "SinkCoverageAnalyser"

    def __init__(self) -> None:
        self.json_string_result = "[]"

    @classmethod
    def get_name(cls):
        return cls.name

    def get_json_string_result(self):
        return self.json_string_result

    def set_json_string_result(self, json_string):
        self.json_string_result = json_string

    def _get_source_file(self, callsite) -> str:
        """
        Dig up the callsitecalltree of a function
        call and get its source file path.
        """
        src_file = callsite.src_function_source_file
        if not src_file:
            parent = callsite.parent_calltree_callsite
            if parent:
                src_file = parent.dst_function_source_file
                src_file = src_file if src_file else ""

        return src_file

    def _get_parent_func_name(self, callsite) -> str:
        """
        Dig up the callsitecalltree of a function
        call and get its parent function name.
        """
        func_file = callsite.src_function_source_file
        if not func_file:
            parent = callsite.parent_calltree_callsite
            if parent:
                func_file = parent.dst_function_name
                func_file = func_file if func_file else ""

        return func_file

    def _retrieve_data_list(
        self,
        proj_profile: project_profile.MergedProjectProfile,
        profiles: List[fuzzer_profile.FuzzerProfile]
    ) -> Tuple[List[cfg_load.CalltreeCallsite], List[function_profile.FunctionProfile]]:
        """
        Retrieve and return full list of call sites and functions
        from all fuzzers profile for this project
        """
        callsite_list = []
        function_list = []
        function_name_list: List[str] = []

        for (key, function) in proj_profile.all_functions.items():
            if key not in function_name_list:
                function_list.append(function)
                function_name_list.append(function.function_name)

        for profile in profiles:
            if profile.function_call_depths is not None:
                callsite_list.extend(cfg_load.extract_all_callsites(profile.function_call_depths))
            for (key, function) in profile.all_class_functions.items():
                if key not in function_name_list:
                    function_list.append(function)
                    function_name_list.append(function.function_name)

        return (callsite_list, function_list)

    def _handle_function_name(
        self,
        callsite: cfg_load.CalltreeCallsite
    ) -> str:
        """
        Add package name to uniquly identify functions
        in different package.
        """
        func_name = f"{callsite.dst_function_name}"
        if func_name.startswith("["):
            return func_name
        else:
            return f"[{callsite.dst_function_source_file}].{func_name}"

    def _map_function_callsite(
        self,
        functions: List[function_profile.FunctionProfile],
        callsites: List[cfg_load.CalltreeCallsite]
    ) -> Dict[str, List[str]]:
        """
        Dig up the callsite for each function and store
        the mapped source location and line number list
        as a formatted string list.
        """
        callsite_dict: Dict[str, List[str]] = dict()

        # Initialize callsite_dict with target function names
        for function in functions:
            callsite_dict[function.function_name] = []

        # Map callsite for all target functions
        for callsite in callsites:
            func_name = self._handle_function_name(callsite)
            if func_name in callsite_dict.keys():
                callsite_dict[func_name].append(
                    "%s#%s:%s" % (
                        self._get_source_file(callsite),
                        self._get_parent_func_name(callsite),
                        callsite.src_linenumber
                    )
                )

        # Sort and make unique for callsites of each function
        for (key, value) in callsite_dict.items():
            callsite_dict[key] = list(set(value))

        return callsite_dict

    def _filter_function_list(
        self,
        functions: List[function_profile.FunctionProfile],
        target_lang: str
    ) -> List[function_profile.FunctionProfile]:
        """
        Filter out target list of functions which are considered
        as sinks for separate langauge which is the major
        analysing target for this SinkAnalyser.
        """
        function_list = []

        # Loop through the all function list for a project
        for fd in functions:
            # Separate handling for different target language
            if target_lang == "c-cpp":
                func_name = utils.demangle_cpp_func(fd.function_name)
                package = ''
            elif target_lang == "python":
                func_name = fd.function_name
                package = fd.function_source_file
                if func_name.startswith("<builtin>."):
                    package, func_name = func_name.split(".", 1)
            elif target_lang == "jvm":
                func_name = fd.function_name.split('(')[0]
                if "." in func_name:
                    package, func_name = func_name.rsplit('.', 1)
                    package = package[1:][:-1]
                else:
                    package = 'default'
            else:
                continue

            # Add the function profile to the result list if it matches one of the target
            if (package, func_name) in SINK_FUNCTION[target_lang]:
                function_list.append(fd)

        return function_list

    def _print_callpath_list(
        self,
        callpath_list: List[List[function_profile.FunctionProfile]]
    ) -> List[str]:
        """
        Pretty print the callpath list
        """
        result_list = []
        for callpath in callpath_list:
            callpath_str = ""
            for item in callpath:
                if callpath_str:
                    callpath_str = f"{callpath_str} -> {item.function_name}"
                else:
                    callpath_str = f"{item.function_name}"
            callpath_str = f"[{callpath_str}]"
            result_list.append(callpath_str)
        return result_list

    def _retrieve_content_rows(
        self,
        functions: List[function_profile.FunctionProfile],
        proj_profile: project_profile.MergedProjectProfile,
        target_lang: str,
        func_callsites: Dict[str, List[str]],
        coverage: code_coverage.CoverageProfile
    ) -> Tuple[str, str]:
        """
        Retrieve the content for this analyser in two formats. One in
        normal html table rows string and the other is in json string
        for generating separate json report for sink coverage that
        could be readable by external analyser.
        """
        html_string = ""
        json_list = []

        for fd in self._filter_function_list(functions, target_lang):
            json_dict: Dict[str, Any] = {}
            callpath_list = proj_profile.get_function_callpaths(fd, [])
            callpath_str = self._print_callpath_list(callpath_list)

            # Loop through the list of calledlocation for this function
            if len(func_callsites[fd.function_name]) == 0:
                html_string += html_helpers.html_table_add_row([
                    f"{fd.function_name}",
                    f"{fd.function_source_file}:{fd.function_linenumber}",
                    "Not in call tree",
                    f"{str(fd.reached_by_fuzzers)}",
                    f"{str(callpath_str)}"
                ])

                json_dict['func_name'] = fd.function_name
                json_dict['func_src'] = f"{fd.function_source_file}:{fd.function_linenumber}"
                json_dict['call_loc'] = "Not in call tree"
                json_dict['fuzzer_reach'] = fd.reached_by_fuzzers
                json_dict['callpaths'] = callpath_str
                json_list.append(json_dict)

                continue

            for called_location in func_callsites[fd.function_name]:
                html_string += html_helpers.html_table_add_row([
                    f"{fd.function_name}",
                    f"{fd.function_source_file}:{fd.function_linenumber}",
                    f"{called_location}",
                    f"{str(fd.reached_by_fuzzers)}"
                    f"{str(callpath_str)}"
                ])

                json_dict['func_name'] = fd.function_name
                json_dict['func_src'] = f"{fd.function_source_file}:{fd.function_linenumber}"
                json_dict['call_loc'] = called_location
                json_dict['fuzzer_reach'] = fd.reached_by_fuzzers
                json_dict['callpaths'] = callpath_str
                json_list.append(json_dict)

        return (html_string, json.dumps(json_list))

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
        Show all used sensitive sink functions / methods in the project and display
        if any fuzzers statically or dynamically reached them. If not, display closest
        entry point to reach them.
        1) Loop through the all function list of the project and see if any of the sink
           functions exists.
        2) Shows if each of those third party function call location is statically
           reachable
        3) Analyse and show closet entry point suggestions for fuzzers developer to
           statically reached those functions / methods
        4) Analyse the fuzzer report to determine if each of those statically reachable
           sink functions / methods has been dynamically coveed by any of the fuzzers
        5) Provide additional entry point to increase the chance of dynamically covering
           those sink functions / methods.
        Remark: json report will be generated instead of html report if tables is None
        """
        logger.info(f" - Running analysis {self.get_name()}")

        # Get full function /  callsite list for all fuzzer's profiles
        callsite_list, function_list = self._retrieve_data_list(proj_profile, profiles)

        # Map callsites to each function
        function_callsite_dict = self._map_function_callsite(function_list, callsite_list)

        # Retrieve table content rows
        html_rows, json_row = self._retrieve_content_rows(
            function_list,
            proj_profile,
            profiles[0].target_lang,
            function_callsite_dict,
            proj_profile.runtime_coverage
        )

        self.set_json_string_result(json_row)
        json_report.add_analysis_json_str_as_dict_to_report(
            self.get_name(),
            self.get_json_string_result()
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
            "This section shows a chosen list of functions / methods "
            "calls and their relative coverage information. By static "
            "analysis of the target project code, all of these function "
            "call and their caller information, including the source file "
            "or class and line number that initiate the call are captured. "
            "The caller source code file or class and the line number are "
            "shown in column 2 while column 1 is the function name of that "
            "selected functions or methods call. Each occurrent of the target "
            "function call will occuply a separate row. Column 3 of each row "
            "indicate if the target function calls is statically unreachable."
            "Column 4 lists all fuzzers (or no fuzzers at all) that have "
            "covered that particular system call in  dynamic fuzzing. Those "
            "functions with low to  no reachability and dynamic hit count indicate "
            "missed fuzzing logic to fuzz and track for possible code injection sinks."
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
                ("Sink source location",
                 "Source file and line number information for the sink function"),
                ("Callsite location",
                 "Source file, line number and parent function of this function call. "
                 "Based on static analysis."),
                ("Reached by fuzzer",
                 "Is this code reachable by any functions? "
                 "Based on static analysis."),
                ("Function call path",
                 "All call path of the project calling to this sink function")
            ]
        )

        html_string += html_rows

        html_string += "</table>"

        html_string += "</div>"  # .collapsible
        html_string += "</div>"  # report-box

        logger.info(f" - Finish running analysis {self.get_name()}")
        return html_string
