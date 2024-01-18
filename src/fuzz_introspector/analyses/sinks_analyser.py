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
"""Analysis plugin for introspection sink functions of interest for different CWE"""

import json
import logging

from bs4 import BeautifulSoup as bs

from typing import (Any, List, Tuple, Dict, Optional)

from fuzz_introspector import (analysis, code_coverage, constants, cfg_load,
                               html_helpers, json_report, utils)

from fuzz_introspector.analyses.data import (cwe_data)

from fuzz_introspector.datatypes import (project_profile, fuzzer_profile,
                                         function_profile)

logger = logging.getLogger(name=__name__)

# List of sink functions for different CWE
SINKS = cwe_data.SINK_FUNCTION
CWES = list(SINKS)


class SinkCoverageAnalyser(analysis.AnalysisInterface):
    """This analyser aims to analyse and generate reports to show the occurrence
    of possible sink functions/methods existed in the target project and if
    those functions/methods are statically reached or dynamically covered
    by any of the fuzzers. If not, it provides the information of the parent
    functions that directly invoke the sink functions and possible call path
    information to reach the parent functions. This information helps the
    fuzzer developers to create fuzzers that target specific sink functions.
    If the target sink function is statically reached by at least a fuzzer but
    it fails to be covered by a fuzzer during runtime, information of the possible
    blocking functions are provided to help the fuzzer developers to modify the
    the fuzzers to make it cover the target sink functions.
    It is one of the analyser class implementing the :class:`analysis.AnalysisInterface`
    class.

    :param json_string_result: JSON result stored when this analyser is first invoked
    :type json_string_result: str
    :param index: Storing the index using to keep track of the separate callpath html
        file generated
    :type index: int
    :param display_html: A boolean value to turn html report generation on and off
    :type display_html: bool
    """
    name: str = "SinkCoverageAnalyser"

    def __init__(self) -> None:
        self.json_string_result = ""
        self.index = 0
        self.handled_sink: Dict[str, str] = {}

    @classmethod
    def get_name(cls):
        """Return the analyser identifying name for processing.

        :return: The identifying name of this analyser
        :rtype: str
        """
        return cls.name

    def get_json_string_result(self):
        """Return the stored json string result.

        :return: The json string result processed and stored
            by this analyser
        :rtype: str
        """
        return f"[{self.json_string_result}]"

    def set_json_string_result(self, json_string):
        """Store the result of this analyser as json string result
        for further processing in a later time.

        :param json_string: A json string variable storing the
            processing result of the analyser for future use
        :type json_string: str
        """
        if len(self.json_string_result) > 0:
            self.json_string_result = self.json_string_result + ", "
        self.json_string_result = self.json_string_result + json_string

    def _get_source_file(self, callsite) -> str:
        """
        Dig up the callsite calltree of a function
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
        Dig up the callsite calltree of a function
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
        self, proj_profile: project_profile.MergedProjectProfile,
        profiles: List[fuzzer_profile.FuzzerProfile]
    ) -> Tuple[List[cfg_load.CalltreeCallsite],
               List[function_profile.FunctionProfile]]:
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
            if profile.fuzzer_callsite_calltree is not None:
                callsite_list.extend(
                    cfg_load.extract_all_callsites(
                        profile.fuzzer_callsite_calltree))
            for (key, function) in profile.all_class_functions.items():
                if key not in function_name_list:
                    function_list.append(function)
                    function_name_list.append(function.function_name)

        return (callsite_list, function_list)

    def _handle_function_name(self,
                              callsite: cfg_load.CalltreeCallsite) -> str:
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
            self, functions: List[function_profile.FunctionProfile],
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
                    "%s#%s:%s" % (self._get_source_file(callsite),
                                  self._get_parent_func_name(callsite),
                                  callsite.src_linenumber))

        # Sort and make unique for callsites of each function
        for (key, value) in callsite_dict.items():
            callsite_dict[key] = list(set(value))

        return callsite_dict

    def _filter_function_list(
            self, functions: List[function_profile.FunctionProfile],
            target_lang: str,
            target_cwe: str) -> List[function_profile.FunctionProfile]:
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
            if (package, func_name) in SINKS[target_cwe]['sink'][target_lang]:
                function_list.append(fd)

        return function_list

    def _retrieve_fuzzer_hitcount(
            self, function: function_profile.FunctionProfile,
            coverage: code_coverage.CoverageProfile) -> int:
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
            target_name: str = "") -> Tuple[str, int]:
        """
        Retrieve source code link for the given function if existed.
        """
        linenumber = function.function_linenumber

        if target_name and target_name in function.callsite.keys():
            try:
                linenumber = int(
                    function.callsite[target_name][0].split(':')[1])
            except ValueError:
                linenumber = -1

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
        self, callpath_list: List[List[function_profile.FunctionProfile]],
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
                    if not proj_profile.runtime_coverage.is_func_hit(
                            callpath_fd.function_name):
                        # if this function is not hit, the parent function is a blocker
                        break
                parent_fd = callpath_fd

            # Fail safe for blocker at the start of the list
            if not parent_fd:
                parent_fd = callpath[0]

            result_list.append(parent_fd)
        return result_list

    def _generate_callpath_page(
            self, callpath: List[function_profile.FunctionProfile],
            proj_profile: project_profile.MergedProjectProfile) -> str:
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
            section += ("</div>" * int(depth_count - 1) * 2 + "</div></div>")

        section += "</div></div></div>"

        html = html_helpers.html_get_header(title="Fuzz introspector")
        html += "<div class='content-wrapper calltree-page'>"
        html += '<div class="content-section calltree-content-section">'
        html += f"{section}</div></div>"
        html += '<script src="calltree.js"></script></body></html>'

        soup = bs(html, "html.parser")
        pretty_html = soup.prettify()
        with open(filename, "w+") as f:
            f.write(pretty_html)

        return filename

    def _filter_inaccessible_callpath(
            self, callpath_list: List[List[function_profile.FunctionProfile]],
            target_lang: str) -> List[List[function_profile.FunctionProfile]]:
        """
        If the target language of this project is jvm, use
        the class and method information to filter out
        call path that is not accessible. Other language
        is not supported yet.
        """
        if target_lang == "jvm":
            result = []

            # Loop through the list of callpaths and
            # filter out inaccessbile callpths
            for callpath in callpath_list:
                if callpath[0].accessible:
                    result.append(callpath)

            return result
        else:
            return callpath_list

    def _handle_callpath_dict(
            self,
            callpath_dict: Dict[function_profile.FunctionProfile,
                                List[List[function_profile.FunctionProfile]]],
            proj_profile: project_profile.MergedProjectProfile,
            target_func: function_profile.FunctionProfile,
            target_lang: str) -> Optional[str]:
        """
        Pretty print index of callpath and generate
        also generate separate html page for displaying
        callpath and add the links to the index.
        """

        if target_func.function_name in self.handled_sink.keys():
            return self.handled_sink[target_func.function_name]
        else:
            html = ""
            count = 0

            for parent_func in callpath_dict.keys():
                func_link, line = self._retrieve_function_link(
                    parent_func, proj_profile, target_func.function_name)
                callpath_list = callpath_dict[parent_func]

                # Filter inaccessible callpaths and sort them
                # by their depth, assuming shallowest depth is
                # the function call closest to the target function
                callpath_list = self._filter_inaccessible_callpath(
                    callpath_list, target_lang)
                callpath_list.sort(key=len)

                for callpath in callpath_list:
                    count += 1
                    if count <= constants.SINK_FUNCTION_CALLPATH_MAX_COUNT:
                        callpath.append(target_func)
                        self.index += 1
                        callpath_link = self._generate_callpath_page(
                            callpath, proj_profile)
                        html += f"<a href='{callpath_link}'>Path {count}</a><br/>"
                    else:
                        break
                if count > constants.SINK_FUNCTION_CALLPATH_MAX_COUNT:
                    break

            if html:
                self.handled_sink[target_func.function_name] = html
                return html
            else:
                return None

    def _print_blocker_list(
            self, blocker_list: List[function_profile.FunctionProfile],
            proj_profile: project_profile.MergedProjectProfile) -> str:
        """
        Print blocker information in html
        """
        if len(blocker_list) == 0:
            return "N/A"

        handled: List[str] = []

        html = "<table><thead>"
        html += "<th bgcolor='#282A36'>Blocker function</th>"
        html += "<th bgcolor='#282A36'>Arguments type</th>"
        html += "<th bgcolor='#282A36'>Return type</th>"
        html += "<th bgcolor='#282A36'>Constants touched</th>"
        html += "</thead><tbody>"
        for blocker in blocker_list:
            if "$lambda" in blocker.function_name or blocker.function_name in handled:
                # Skip repeat blockers
                continue
            handled.append(blocker.function_name)
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
            self, functions: List[function_profile.FunctionProfile],
            proj_profile: project_profile.MergedProjectProfile,
            target_lang: str, func_callsites: Dict[str, List[str]],
            coverage: code_coverage.CoverageProfile,
            cwe: str) -> Tuple[str, str]:
        """
        Retrieve the content for this analyser for a specific cwe
        in two formats. One in normal html table rows string and the
        other is in json string for generating separate json report
        for sink coverage that could be readable by external analyser.
        """
        html_string = ""
        json_list = []

        for fd in self._filter_function_list(functions, target_lang, cwe):
            json_dict: Dict[str, Any] = {}
            callpath_list, callpath_name_list = proj_profile.get_function_callpaths(
                fd, [])
            callpath_dict = utils.group_path_list_by_target(callpath_list)
            callpath_name_dict = utils.group_path_list_by_target(
                callpath_name_list)

            if len(fd.reached_by_fuzzers) == 0:
                fuzzer_callpath = self._handle_callpath_dict(
                    callpath_dict, proj_profile, fd, target_lang)

                if not fuzzer_callpath:
                    # No reachable call path found for this sink
                    # functions, possibly false positive, skipping it
                    continue

                blocker = "N/A"
            else:
                fuzzer_callpath = "N/A"

                # There are fuzzers statically reach the target functions
                # Check if any fuzzers dynamically reached the target functions
                # If not, determine blockers of the sink functions
                if self._retrieve_fuzzer_hitcount(fd, coverage) == 0:
                    blocker_list = self._determine_branch_blocker(
                        callpath_list, proj_profile)
                    blocker = self._print_blocker_list(blocker_list,
                                                       proj_profile)
                else:
                    blocker = "N/A"

            if self.display_html:
                row = html_helpers.html_table_add_row([
                    f"{fd.function_name}", f"{str(fd.reached_by_fuzzers)}",
                    fuzzer_callpath, f"{blocker}"
                ])

                if blocker != "N/A":
                    row_split = row.rsplit('<td><table>', 1)
                    row = f'{row_split[0]}<td style="max-width: 600px"><table>{row_split[1]}'

                html_string += row

            json_dict['func_name'] = fd.function_name
            json_dict['fuzzer_reach'] = fd.reached_by_fuzzers
            json_dict['callpaths'] = callpath_name_dict
            json_dict['blocker'] = blocker
            json_list.append(json_dict)

        cwe_json: Dict[str, Any] = {}
        cwe_json[cwe] = json_list

        return (html_string, json.dumps(cwe_json))

    def analysis_func(self,
                      table_of_contents: html_helpers.HtmlTableOfContents,
                      tables: List[str],
                      proj_profile: project_profile.MergedProjectProfile,
                      profiles: List[fuzzer_profile.FuzzerProfile],
                      basefolder: str, coverage_url: str,
                      conclusions: List[html_helpers.HTMLConclusion]) -> str:
        """
        Performs an analysis based on the sink function discovery and analysis.
        Show all possible sensitive sink functions/methods for each supported
        CWE found in the project and display if any fuzzers statically or
        dynamically reached them. If no fuzzers statically reach the specific
        sink function and it does exist in the project, display the possible
        call path that could reach that sink function. For each sink function
        found, it may have more than one accessible call path, the maximum
        number of call paths generated is configurable by the variable
        SINK_FUNCTION_CALLPATH_MAX_COUNT in constants.py. If there exist
        fuzzers that statically reach a specific sink function but no dynamical
        reaching path is found, then the possible blocking functions together
        with their information are displayed to help the developer to update
        their fuzzers. Currently, The OWASP top 10 CWEs are supported on
        c-cpp/python/java language. All the possible sink functions for each
        CWE are stored in data/cwe_data.py. Support for more CWEs or refining
        the sink functions for each CWE could be done by modifying the
        cwe_data.py. A simple processing flow of the sink analyser for each
        supported CWE is shown below.
            1) Loop through the all functions list of the project and see if
               any of the sink functions exist.
            2) Show, if any, fuzzers statically reach the target sink function
            3) Discover and display the call path tree to reach each of the
               sink functions if it is not statically reached by any fuzzers.
               For each of the sink functions, only display the top few call
               paths that are publicly accessible. The number of call paths
               displayed is configurable in constants.py.
            4) Provide blocker information for those sink functions that are
               statically covered but not dynamically covered to help the
               developer to update their fuzzers.
        Remark: JSON report will be generated, and HTML report will only be generated
        if the display_html variable of this analyser is set to True.
        Please also refer to :class:`calltree_analysis.FuzzCalltreeAnalysis`

        :param table_of_contents: The object that handle the table of contents generation
            for the html report
        :type table_of_contents: html_helpers.HtmlTableOfContents
        :param tables: List of html strings for each table to be included in the html
            report, if it is empty or display_html is False, there will be no html report
            generated for this analyser
        :type tables: List[str]
        :param proj_profile: The object storing all the information for this fuzzing project
        :type proj_profile: project_profile.MergedProjectProfile
        :param profiles: The object list storing the information of each fuzzers for this
            fuzzing project
        :type profiles: List[fuzzer_profile.FuzzerProfile]
        :param basefolder: The path of the base directory for this fuzz-introspector run
        :type basefolder: str
        :param coverage_url: The base URL of the coverage report for this session on this
            fuzzing project
        :type coverage_url: str
        :param conclusions: The object list handling the conclusion session of the html report
        :type conclusions:  List[html_helpers.HTMLConclusion]
        """
        logger.info(f" - Running analysis {self.get_name()}")

        # Get full function /  callsite list for all fuzzer's profiles
        callsite_list, function_list = self._retrieve_data_list(
            proj_profile, profiles)

        # Map callsites to each function
        function_callsite_dict = self._map_function_callsite(
            function_list, callsite_list)

        html_string = ""
        html_string += "<div class=\"report-box\">"

        html_string += html_helpers.html_add_header_with_link(
            "Sink analyser for CWEs", html_helpers.HTML_HEADING.H1,
            table_of_contents)

        # Table with all function calls for each files
        html_string += "<div class=\"collapsible\">"
        html_string += (
            "<p>"
            "This section contains multiple tables, each table "
            "contains a list of sink functions/methods found in "
            "the project for one of the CWE supported by the sink "
            "analyser, together with information like which fuzzers "
            "statically reach the sink functions/methods and possible "
            "call path to that sink functions/methods if it is not "
            "statically reached by any fuzzers. Column 1 is the "
            "function/method name of the sink functions/methods found "
            "in the project. Column 2 lists all fuzzers (or no fuzzers "
            "at all) that have covered that particular function method "
            "statically. Column 3 shows a list of possible call paths "
            "to reach the specific function/method call if none of the "
            "fuzzers cover the target function/method calls. Lastly, "
            "column 4 shows possible fuzzer blockers that prevent an "
            "existing fuzzer from reaching the target sink functions/methods "
            "dynamically."
            "</p>")

        for cwe in CWES:
            logger.info(f" - Running analysis {self.get_name()} for {cwe}")

            # Retrieve table content rows
            html_rows, json_row = self._retrieve_content_rows(
                function_list, proj_profile, profiles[0].target_lang,
                function_callsite_dict, proj_profile.runtime_coverage, cwe)

            self.set_json_string_result(json_row)

            # If no html, this is our job done for this cwe
            if not self.display_html:
                continue

            html_string += html_helpers.html_add_header_with_link(
                f"Sink functions/methods found for {cwe}",
                html_helpers.HTML_HEADING.H2, table_of_contents)

            # Third party function calls table
            tables.append(f"myTable{len(tables)}")
            html_string += html_helpers.html_create_table_head(
                tables[-1],
                [("Target sink", ""),
                 ("Reached by fuzzer",
                  "Is this code reachable by any fuzzer functions? "
                  "Based on static analysis."),
                 ("Function call path",
                  "All call paths of the project calling to each sink function. "
                  "This column is only shown if no fuzzer statically reached "
                  "the target sink function."),
                 ("Possible branch blockers",
                  "Determine which branch blockers avoid fuzzers to cover the"
                  "sink function during runtime and its information. This column "
                  "is only shown if there is fuzzer statically reached the "
                  "target sink function but failed to reach it dynamically.")])

            html_string += html_rows
            html_string += "</table>"

        html_string += "</div>"  # .collapsible
        html_string += "</div>"  # report-box

        json_report.add_analysis_json_str_as_dict_to_report(
            self.get_name(), self.get_json_string_result())

        logger.info(f" - Finish running analysis {self.get_name()}")

        if self.display_html:
            return html_string
        else:
            return ""
