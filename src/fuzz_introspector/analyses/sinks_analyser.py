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

from bs4 import BeautifulSoup as bs

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
#        self.display_html = False
        self.display_html = True
        self.index = 0

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

    def _retrieve_fuzzer_hitcount(
        self,
        function: function_profile.FunctionProfile,
        coverage: code_coverage.CoverageProfile
    ) -> int:
        """
        Analyse the project coverage and calculate the hit
        count for target function. This information also shows
        if the target function is covered by a specific fuzzer
        during runtime.
        """
        count = 0
        for parent_func in function.incoming_references:
            try:
                lineno = int(function.function_linenumber)
            except ValueError:
                continue
            if coverage.is_func_lineno_hit(parent_func, lineno):
                count += 1
        return count

    def _retrieve_function_link(
        self,
        function: function_profile.FunctionProfile,
        proj_profile: project_profile.MergedProjectProfile,
        target_name: str = ""
    ) -> Tuple[str, int]:
        """
        Retrieve source code link for the given function if existed.
        """
        linenumber = function.function_linenumber

        if target_name and target_name in function.callsite.keys():
            linenumber = int(function.callsite[target_name][0].split(':')[1])

        link = proj_profile.resolve_coverage_report_link(
            proj_profile.coverage_url,
            function.function_source_file,
            linenumber,
            function.function_name,
        )

        if utils.check_coverage_link_existence(link):
            return (link, linenumber)
        else:
            return ("#", linenumber)

    def _determine_branch_blocker(
        self,
        callpath_list: List[List[function_profile.FunctionProfile]],
        proj_profile: project_profile.MergedProjectProfile
    ) -> List[function_profile.FunctionProfile]:
        """
        Determine the branch blocker list that affect the runtime
        coverage of the target function.
        """
        result_list = []
        for callpath in callpath_list:
            # Fail safe for empty callpath
            if len(callpath) == 0:
                continue

            # Loop through all possible callpath to determine blocking function
            parent_fd = None
            for callpath_fd in callpath:
                if parent_fd:
                    if not proj_profile.runtime_coverage.is_func_hit(callpath_fd.function_name):
                        # if this function is not hit, the parent function is a blocker
                        break
                parent_fd = callpath_fd

            # Fail safe for blocker at the start of the list
            if not parent_fd:
                parent_fd = callpath[0]

            result_list.append(parent_fd)
        return result_list

    def _generate_callpath_page(
        self,
        callpath: List[function_profile.FunctionProfile],
        proj_profile: project_profile.MergedProjectProfile
    ) -> str:
        """
        Generate a standalone html page to display
        the given callpath, also providing function
        call location information.
        """
        filename = f"sink_function_callpath_{self.index}.html"

        depth_count = 0
        section = "<h1>Sink Function Callpath</h1>"
        section += "<div id=\"calltree-wrapper\">"
        section += "<div class='call-tree-section-wrapper'>"
        for fd in callpath:
            indentation = "%dpx" % (int(depth_count) * 16 + 100)
            link, line = self._retrieve_function_link(fd, proj_profile)

            section += "<div class='red-background coverage-line'>"
            section += f"""<span class="coverage-line-inner" data-calltree-idx="{depth_count:05}"
                data-paddingleft="{indentation}" style="padding-left: {indentation}">
                <span class="node-depth-wrapper">{depth_count}</span>
                    <code class="language-clike">
                        {fd.function_name}
                    </code>
                    <span class="coverage-line-filename">
                        in <a href="{link}">
                            {fd.function_source_file}:{line}
                        </a>
                        <span class="calltree-idx">
                            {depth_count:05}
                        </span>
                    </span>
                </span>"""
            section += f"""<div class="calltree-line-wrapper open level-{depth_count}
                data-paddingleft="{indentation}">"""

            depth_count += 1

        # Ending all opened <div>
        if depth_count == 1:
            section += "</div></div>"
        else:
            section += (
                "</div>" * int(depth_count - 1) * 2 + "</div></div>"
            )

        section += "</div></div></div>"

        html = html_helpers.html_get_header(calltree=True, title="Fuzz introspector")
        html += '<div class="content-section calltree-content-section">'
        html += f"{section}</div></div>"
        html += '<script src="calltree.js"></script></body></html>'

        soup = bs(html, "html.parser")
        pretty_html = soup.prettify()
        with open(filename, "w+") as f:
            f.write(pretty_html)

        return filename

    def _handle_callpath_dict(
        self,
        callpath_dict: Dict[
            function_profile.FunctionProfile,
            List[List[function_profile.FunctionProfile]]
        ],
        proj_profile: project_profile.MergedProjectProfile,
        target_name: str
    ) -> str:
        """
        Pretty print index of callpath and generate
        also generate separate html page for displaying
        callpath and add the links to the index.
        """
        if len(callpath_dict.keys()) == 0:
            return "N/A"

        html = "<table><thead>"
        html += "<th bgcolor='#282A36'>Parent functions</th>"
        html += "<th bgcolor='#282A36'>Callpaths</th>"
        html += "</thead><tbody>"

        for parent_func in callpath_dict.keys():
            func_link, line = self._retrieve_function_link(parent_func, proj_profile, target_name)
            callpath_list = callpath_dict[parent_func]
            html += "<tr><td style='max-width: 150px'>"
            html += f"{parent_func.function_name}<br/>"
            html += f"in <a href='{func_link}'>"
            html += f"{parent_func.function_source_file}:{line}</a>"
            html += "</td><td>"
            count = 0

            # Sort callpath by its depth, assuming shallowest depth is
            # the function call closest to the target function
            callpath_list.sort(key=len)

            for callpath in callpath_list:
                count += 1
                self.index += 1
                callpath_link = self._generate_callpath_page(callpath, proj_profile)
                if count <= 20:
                    html += f"<a href='{callpath_link}'>Path {count}</a><br/>"
            html += "</td></tr>"

        html += "</tbody></table>"

        return html

    def _print_blocker_list(
        self,
        blocker_list: List[function_profile.FunctionProfile],
        proj_profile: project_profile.MergedProjectProfile
    ) -> str:
        """
        Print blocker information in html
        """
        if len(blocker_list) == 0:
            return "N/A"

        html = "<table><thead>"
        html += "<th bgcolor='#282A36' >Blocker function</th>"
        html += "<th bgcolor='#282A36'>Arguments type</th>"
        html += "<th bgcolor='#282A36'>Return type</th>"
        html += "<th bgcolor='#282A36'>Constants touched</th>"
        html += "</thead><tbody>"
        for blocker in blocker_list:
            link, line = self._retrieve_function_link(blocker, proj_profile)
            html += f"<tr><td style='max-width: 150px'>{blocker.function_name}<br/>"
            html += f"in <a href='{link}'>"
            html += f"{blocker.function_source_file}:{line}</a>"
            html += "</td>"
            html += f"<td style='max-width: 150px'>{str(blocker.arg_types)}</td>"
            html += f"<td style='max-width: 150px'>{str(blocker.return_type)}</td>"
            html += f"<td style='max-width: 150px'>{str(blocker.constants_touched)}</td></tr>"
        html += "</tbody></table>"
        return html

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
            parent_list, parent_name_list = proj_profile.get_direct_parent_list(fd)
            callpath_list, callpath_name_list = proj_profile.get_function_callpaths(fd, [])
            callpath_dict = utils.group_path_list_by_target(callpath_list)
            callpath_name_dict = utils.group_path_list_by_target(callpath_name_list)

            fuzzer_cover_count = self._retrieve_fuzzer_hitcount(fd, coverage)
            if fuzzer_cover_count == 0:
                blocker_list = self._determine_branch_blocker(
                    callpath_list,
                    proj_profile
                )
                blocker = self._print_blocker_list(blocker_list, proj_profile)
            else:
                blocker = "N/A"

            # Loop through the list of calledlocation for this function
            if len(func_callsites[fd.function_name]) == 0:
                if self.display_html:
                    row = html_helpers.html_table_add_row([
                        f"{fd.function_name}",
                        "Not in fuzzer provided call tree",
                        f"{str(fd.reached_by_fuzzers)}",
                        self._handle_callpath_dict(callpath_dict, proj_profile, fd.function_name),
                        f"{fuzzer_cover_count}",
                        f"{blocker}"
                    ])

                    if blocker != "N/A":
                        row_split = row.rsplit('<td><table>', 1)
                        row = f'{row_split[0]}<td style="max-width: 600px"><table>{row_split[1]}'
                        html_string += row

                json_dict['func_name'] = fd.function_name
                json_dict['call_loc'] = "Not in fuzzer provided call tree"
                json_dict['fuzzer_reach'] = fd.reached_by_fuzzers
                json_dict['parent_func'] = parent_name_list
                json_dict['callpaths'] = callpath_name_dict
                json_dict['fuzzer_cover'] = f"{fuzzer_cover_count}"
                json_dict['blocker'] = blocker
                json_list.append(json_dict)

                continue

            for called_location in func_callsites[fd.function_name]:
                if self.display_html:
                    row = html_helpers.html_table_add_row([
                        f"{fd.function_name}",
                        f"{called_location}",
                        f"{str(fd.reached_by_fuzzers)}",
                        self._handle_callpath_dict(callpath_dict, proj_profile, fd.function_name),
                        f"{fuzzer_cover_count}",
                        f"{blocker}"
                    ])

                    if blocker != "N/A":
                        row_split = row.rsplit('<td><table>', 1)
                        row = f'{row_split[0]}<td style="max-width: 600px"><table>{row_split[1]}'
                        html_string += row

                json_dict['func_name'] = fd.function_name
                json_dict['call_loc'] = called_location
                json_dict['fuzzer_reach'] = fd.reached_by_fuzzers
                json_dict['parent_func'] = parent_name_list
                json_dict['callpaths'] = callpath_name_dict
                json_dict['fuzzer_cover'] = f"{fuzzer_cover_count}"
                json_dict['blocker'] = blocker
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
        entry point to reach them
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

        # If no html, this is our job done
        if not self.display_html:
            return ""

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
            "Column 1 is the function name of that selected functions or "
            "methods. Column 2 of each row indicate if the target function "
            "covered by any fuzzer calltree information. Column 3 lists all "
            "fuzzers (or no fuzzers at all) that have coered that particular "
            "function call dynamically. Column 4 shows list of parent function "
            "for the specific function call, while column 5 shows possible blocker "
            "functions that make the fuzzers fail to reach the specific functions. "
            "Both column 4 and 5 will only show information if none of the fuzzers "
            "cover the target function calls."
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
                 "Source file, line number and parent function of sink function call. "
                 "Based on static analysis and provided by .data calltree."),
                ("Reached by fuzzer",
                 "Is this code reachable by any fuzzer functions? "
                 "Based on static analysis."),
                ("Function call path",
                 "All call path of the project calling to each sink function. "
                 "Group by functions directly calling the sink function."),
                ("Covered by fuzzer",
                 "Number of fuzzers covering this sink function during runtime."),
                ("Possible branch blockers",
                 "Determine which branch blockers avoid fuzzers to cover the"
                 "sink function during runtime and its information")
            ]
        )

        html_string += html_rows
        html_string += "</table>"
        html_string += "</div>"  # .collapsible
        html_string += "</div>"  # report-box

        logger.info(f" - Finish running analysis {self.get_name()}")
        return html_string
