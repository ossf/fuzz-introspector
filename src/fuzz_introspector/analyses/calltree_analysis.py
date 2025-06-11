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
"""Logic related to calltree analysis"""

import os
import logging
import html
import json
import random
import string

from typing import (
    Dict,
    List,
    Optional,
)

from fuzz_introspector import analysis
from fuzz_introspector import utils
from fuzz_introspector import cfg_load
from fuzz_introspector import html_helpers
from fuzz_introspector.datatypes import project_profile, fuzzer_profile

# For pretty printing the html code:
from bs4 import BeautifulSoup as bs

logger = logging.getLogger(name=__name__)


class FuzzCalltreeAnalysis(analysis.AnalysisInterface):
    name: str = "FuzzCalltreeAnalysis"

    def __init__(self) -> None:
        logger.info("Creating FuzzCalltreeAnalysis")
        self.json_string_result = "[]"
        self.dump_files = True

    @classmethod
    def get_name(cls):
        return cls.name

    def get_json_string_result(self):
        """Helper for getting json string"""
        return self.json_string_result

    def set_json_string_result(self, json_string):
        """Helper for setting json string"""
        self.json_string_result = json_string

    def analysis_func(self,
                      table_of_contents: html_helpers.HtmlTableOfContents,
                      tables: List[str],
                      proj_profile: project_profile.MergedProjectProfile,
                      profiles: List[fuzzer_profile.FuzzerProfile],
                      basefolder: str, coverage_url: str,
                      conclusions: List[html_helpers.HTMLConclusion],
                      out_dir) -> str:
        """
        Creates the HTML of the calltree. Returns the HTML as a string.
        """
        logger.info("Not implemented")

        return ""

    def _get_span_row(self, ct_idx_str, indentation, node, demangled_name,
                      func_href, callsite_link):
        span_row = f"""<span class="coverage-line-inner" data-calltree-idx="{ct_idx_str}"
        data-paddingleft="{indentation}" style="padding-left: {indentation}">
            <span class="node-depth-wrapper">{node.depth}</span>
            <code class="language-clike">
                {html.escape(demangled_name)}
            </code>
            <span class="coverage-line-filename">
                {func_href}
                <a href="{callsite_link}">
                    [call site]
                </a>
                <span class="calltree-idx">{ct_idx_str}</span>
            </span>
        </span>"""
        return span_row

    def create_calltree(self, profile: fuzzer_profile.FuzzerProfile,
                        out_dir) -> str:
        logger.info("In calltree")
        # Generate HTML for the calltree
        calltree_html_string = "<h1>Fuzzer calltree</h1>"
        calltree_html_string += "<div id=\"calltree-wrapper\">"

        calltree_html_section_string = "<div class='call-tree-section-wrapper'>"
        nodes = cfg_load.extract_all_callsites(
            profile.fuzzer_callsite_calltree)

        for i, node in enumerate(nodes):
            # All divs created in this loop must also be closed in this loop.
            if profile.target_lang == "jvm":
                demangled_name = utils.demangle_jvm_func(
                    node.dst_function_source_file, node.dst_function_name)
            elif profile.target_lang == "rust":
                demangled_name = utils.demangle_rust_func(
                    node.dst_function_name)
            else:
                demangled_name = utils.demangle_cpp_func(
                    node.dst_function_name)

            # Prepare strings needed in the HTML
            color_to_be = node.cov_color
            callsite_link = node.cov_callsite_link
            link = node.cov_link
            ct_idx_str = self.create_str_node_ctx_idx(str(node.cov_ct_idx))

            # Only display [function] link if we have, otherwise show no
            # [function] text.
            if node.dst_function_source_file.replace(" ", "") != "":
                func_href = f"""<a href="{link}">[function]</a>"""
            else:
                func_href = ""

            # indentation in html:
            indentation = "%dpx" % (int(node.depth) * 16 + 100)

            if i > 0:
                previous_node = nodes[i - 1]
                if previous_node.depth == node.depth:
                    calltree_html_section_string += "</div>"
                elif previous_node.depth > node.depth:
                    # We need to close one coverage-line and one
                    # calltree-line-wrapper for each depth, as well as the
                    # row itself.
                    node_difference = int(previous_node.depth - node.depth)
                    divs_to_close = node_difference * 2 + 1
                    closing_divs = "</div>" * divs_to_close

                    calltree_html_section_string += closing_divs

            # Add div for line itself.
            calltree_html_section_string += (
                f"<div class=\"{color_to_be}-background coverage-line\">")
            calltree_html_section_string += self._get_span_row(
                ct_idx_str, indentation, node, demangled_name, func_href,
                callsite_link)

            # If we are not at end
            if i < len(nodes) - 1:
                next_node = nodes[i + 1]

                # If depth is increasing then we should open a new div for
                # folding the calltree.
                if next_node.depth > node.depth:
                    calltree_html_section_string += f"""<div
        class="calltree-line-wrapper open level-{int(node.depth)}"
         data-paddingleft="{indentation}" >"""

            # If we are at end, then we should close the remainding divs:
            # - the depth
            # - the current new node.
            if i == len(nodes) - 1:
                logger.info("At end")
                # In terms of divs, we need to close one coverage-line and one
                # calltree-line-wrapper for each depth. Minus one line-wrapper
                # for the level we did not take.
                if node.depth == 1:
                    calltree_html_section_string += "</div></div>"
                elif node.depth > 1:
                    calltree_html_section_string += (
                        "</div>" * int(node.depth - 1) * 2 + "</div></div>")

        # Close the opening two divs
        calltree_html_section_string += "</div>"  # opening node
        calltree_html_section_string += "</div>"  # call-tree-section-wrapper

        # Side overview wrapper holds the vertical bitmap image. The actual
        # visualisation happens in javascript rather than here.
        calltree_html_section_string += "<div id=\"side-overview-wrapper\"></div>"

        logger.info('calltree_html_section_string: <divs>: %d -- </divs>: %d',
                    calltree_html_section_string.count("<div"),
                    calltree_html_section_string.count("</div>"))

        calltree_html_string += calltree_html_section_string + "</div>"  # calltree-wrapper
        logger.info("Calltree created")

        # Write the HTML to a file called calltree_view_XX.html where XX is a counter.
        calltree_file_idx = 0
        calltree_html_file = os.path.join(
            out_dir, f"calltree_view_{calltree_file_idx}.html")
        while os.path.isfile(calltree_html_file):
            calltree_file_idx += 1
            calltree_html_file = os.path.join(
                out_dir, f"calltree_view_{calltree_file_idx}.html")

        self.html_create_dedicated_calltree_file(
            calltree_html_string,
            calltree_html_file,
            profile,
        )
        return calltree_html_file

    def collect_calltree_nodes(
        self, branch_blockers: List[analysis.FuzzBranchBlocker],
        func_call_depth: Optional[cfg_load.CalltreeCallsite]
    ) -> Dict[analysis.FuzzBranchBlocker, cfg_load.CalltreeCallsite]:
        """Map branch blockers to the calltree nodes"""

        all_callsites = cfg_load.extract_all_callsites(func_call_depth)
        nodes_num = len(all_callsites)
        if nodes_num == 0:
            logger.error(
                "Failed to extract callsites, "
                "the blocker table won't have correct links to calltree.")

        blocker_node_map: Dict[analysis.FuzzBranchBlocker,
                               cfg_load.CalltreeCallsite] = {}
        for blocker in branch_blockers:
            func_name = blocker.function_name
            branch_linenumber = int(blocker.branch_line_number)
            for idx, node in enumerate(all_callsites):
                if func_name == node.dst_function_name:
                    depth = node.depth + 1
                    found_node = node
                    # Try to adjust the blocker node in the callees of the
                    # current func.
                    for i in range(idx + 1, nodes_num):
                        new_node = all_callsites[i]
                        if depth > new_node.depth:
                            break  # Reached the caller of the node
                        if (depth == new_node.depth and branch_linenumber
                                >= new_node.src_linenumber):
                            found_node = new_node
                    blocker_node_map[blocker] = found_node
                    break

        return blocker_node_map

    def html_create_dedicated_calltree_file(
            self, calltree_html_string: str, filename: str,
            profile: fuzzer_profile.FuzzerProfile) -> None:
        """
        Write a wrapped HTML file with the tags needed from fuzz-introspector
        We use this only for wrapping calltrees at the moment, however, down
        the line it makes sense to have an easy wrapper for other HTML pages
        too.
        """
        complete_html_string = ""
        blocker_infos = {}
        # HTML start
        html_header = html_helpers.html_get_header(
            title=f"Fuzz introspector: { profile.identifier }")
        html_header += "<div class='content-wrapper calltree-page'>"
        html_header += '<div class="content-section calltree-content-section">'
        complete_html_string += html_header

        # Display fuzz blocker at top of page
        if profile.branch_blockers:
            blockers_node_map = self.collect_calltree_nodes(
                profile.branch_blockers[:12], profile.fuzzer_callsite_calltree)
            # Record the link to coverage report for the branch blocker.
            for b_blocker, ct_node in blockers_node_map.items():
                idx = self.create_str_node_ctx_idx(str(ct_node.cov_ct_idx))
                blocker_infos[idx] = b_blocker.coverage_report_link

            fuzz_blocker_table = self.create_branch_blocker_table(
                profile, [], "", 12)
        else:
            fuzz_blocker_nodes = self.get_fuzz_blockers(
                profile, max_blockers_to_extract=12)

            fuzz_blocker_table = self.create_fuzz_blocker_table(
                profile, [], "", fuzz_blockers=fuzz_blocker_nodes)

            for node in fuzz_blocker_nodes:
                # The link to coverage report is not present in this type of blockers.
                blocker_infos[self.create_str_node_ctx_idx(str(
                    node.cov_ct_idx))] = ""

        if fuzz_blocker_table is not None:
            complete_html_string += "<div class=\"report-box\">"
            complete_html_string += "<h1>Fuzz blockers</h1>"
            complete_html_string += fuzz_blocker_table
            complete_html_string += "</div>"

        complete_html_string += calltree_html_string

        # HTML end
        # close html header and content-section calltree-content-section
        html_end = '</div></div>'

        if len(blocker_infos) > 0:
            html_end += "<script>"
            html_end += f'var fuzz_blocker_infos = \'{json.dumps(blocker_infos)}\';'
            html_end += "</script>"

        html_end += "<script src=\"calltree.js\"></script>"
        complete_html_string += html_end

        complete_html_string += "</body></html>"

        # Beautify and write HTML
        soup = bs(complete_html_string, "html.parser")
        pretty_html = soup.prettify()
        if self.dump_files:
            with open(filename, "w+") as cf:
                cf.write(pretty_html)

    def create_str_node_ctx_idx(self, cov_ct_idx: str) -> str:
        prefixed_zeros = "0" * (len("00000") - len(cov_ct_idx))
        return f"{prefixed_zeros}{cov_ct_idx}"

    def get_fuzz_blockers(
            self,
            profile: fuzzer_profile.FuzzerProfile,
            max_blockers_to_extract: int = 999
    ) -> List[cfg_load.CalltreeCallsite]:
        """Gets a list of fuzz blockers"""
        blocker_list: List[cfg_load.CalltreeCallsite] = []

        # Extract all callsites in calltree and exit early if none
        all_callsites = cfg_load.extract_all_callsites(
            profile.fuzzer_callsite_calltree)
        if len(all_callsites) == 0:
            return blocker_list

        # Filter nodes that has forward reds. Extract maximum
        # max_blockers_to_extract nodes.
        nodes_sorted_by_red_ahead = sorted(all_callsites,
                                           key=lambda x: x.cov_forward_reds,
                                           reverse=True)
        for node in nodes_sorted_by_red_ahead:
            if node.cov_forward_reds == 0 or len(
                    blocker_list) >= max_blockers_to_extract:
                break
            blocker_list.append(node)
        return blocker_list

    def create_fuzz_blocker_table(
            self,
            profile: fuzzer_profile.FuzzerProfile,
            tables: List[str],
            calltree_file_name: str,
            fuzz_blockers: Optional[List[cfg_load.CalltreeCallsite]] = None,
            file_link: Optional[str] = None) -> Optional[str]:
        """
        Creates HTML string for table showing fuzz blockers.
        """
        logger.info("Creating fuzz blocker table")

        # Get the fuzz blockers
        if fuzz_blockers is None:
            fuzz_blockers = self.get_fuzz_blockers(profile,
                                                   max_blockers_to_extract=12)
        if len(fuzz_blockers) == 0:
            return None

        html_table_string = "<p class='no-top-margin'>The following nodes " \
                            "represent call sites where fuzz blockers occur.</p>"
        tables.append(f"myTable{len(tables)}")
        html_table_string += html_helpers.html_create_table_head(
            tables[-1],
            [("Amount of callsites blocked",
              "Total amount of callsites blocked"),
             ("Calltree index",
              "Index in call tree where the fuzz blocker is."),
             ("Parent function",
              "Function in which the call site that blocks resides."),
             ("Callsite", ""),
             ("Largest blocked function",
              "This is the function with highest cyclomatiic complexity amongst"
              "all of the functions that are blocked. As such, it's a way of "
              "highlighting a potentially important function being blocked")],
            sort_by_column=0,
            sort_order="desc")
        for node in fuzz_blockers:
            link_prefix = "0" * (5 - len(str(node.cov_ct_idx)))
            node_id = f'{link_prefix}{node.cov_ct_idx}'
            if file_link is not None:
                cs_link = (
                    "<span class=\"text-link\">"
                    f"<a href=\"{file_link}?scrollToNode={node_id}\">call site: {node_id}"
                    "</a></span>")
            else:
                cs_link = ("<span class=\"text-link\" "
                           f"onclick=\" scrollToNodeInCT('{node_id}')\">"
                           f"call site: {node_id}</span>")
            html_table_string += html_helpers.html_table_add_row([
                str(node.cov_forward_reds),
                str(node.cov_ct_idx), node.cov_parent, cs_link,
                node.cov_largest_blocked_func
            ])
        html_table_string += "</table>"

        return html_table_string

    def create_branch_blocker_table(
            self, profile: fuzzer_profile.FuzzerProfile, tables: List[str],
            file_link: str, max_number_of_blockers: int) -> Optional[str]:
        """
        Creates HTML string for table showing branch blockers.
        """
        logger.info("Creating branch blocker table")

        branch_blockers = profile.branch_blockers[:max_number_of_blockers]
        if len(branch_blockers) == 0:
            return None

        random_suffix = '_' + ''.join(
            random.choices(string.ascii_lowercase + string.ascii_uppercase,
                           k=7))

        blockers_node_map = self.collect_calltree_nodes(
            branch_blockers, profile.fuzzer_callsite_calltree)

        html_table_string = "<p class='no-top-margin'>The followings are " \
                            "the branches where fuzzer fails to bypass.</p>"
        tables.append(f"myTable{len(tables)}")

        branch_table_rows = [
            ("Unique non-covered Complexity",
             "Cyclomatic Complexity of not-yet-covered functions reachable "
             "by the blocked branch side."),
            ("Unique Reachable Complexities",
             "Cyclomatic Complexity of the functions reachable by the blocked branch side."
             ),
            ("Unique Reachable Functions",
             "List of functions that only the blocked branch side can reach."),
            ("All non-covered Complexity",
             "Cyclomatic Complexity that is not covered because of blockage."),
            ("All Reachable Complexity",
             "Cyclomatic Complexity that the blocked branch-side can reach."),
            ("Function Name", "Function containing the blocked branch."),
            ("Function Callsite",
             "The blocking function callsite in the calltree"),
            ("Blocked Branch",
             "The line of code corresponding to the blocked branch"),
        ]
        html_table_string += html_helpers.html_create_table_head(
            tables[-1], branch_table_rows, sort_by_column=0, sort_order="desc")
        for entry in branch_blockers:
            if entry in blockers_node_map:
                calltree_idx = blockers_node_map[entry].cov_ct_idx
            else:
                logger.error("The calltree index is not valid!")
                calltree_idx = 0
            link_prefix = "0" * (5 - len(str(calltree_idx)))
            node_id = "%s%s" % (link_prefix, calltree_idx)
            if file_link is not None:
                cs_link = (
                    "<span class=\"text-link\">"
                    f"<a href=\"{file_link}?scrollToNode={node_id}\">call site: {node_id}"
                    "</a></span>")
            else:
                cs_link = ("<span class=\"text-link\" "
                           f"onclick=\" scrollToNodeInCT('{node_id}')\">"
                           f"call site: {node_id}</span>")
            collapsible_id = entry.source_file + entry.blocked_side_line_numder + random_suffix
            func_num = len(entry.blocked_unique_funcs)
            if func_num > 0:
                collapsible_string = html_helpers.create_collapsible_element(
                    str(func_num), entry.blocked_unique_funcs, collapsible_id)
            else:
                collapsible_string = "None"

            if profile.target_lang == "rust":
                entry_function_name = utils.demangle_rust_func(
                    entry.function_name)
            else:
                entry_function_name = utils.demangle_cpp_func(
                    entry.function_name)

            html_table_string += html_helpers.html_table_add_row([
                str(entry.blocked_unique_not_covered_complexity),
                str(entry.blocked_unique_reachable_complexity),
                collapsible_string,
                str(entry.blocked_not_covered_complexity),
                str(entry.blocked_reachable_complexity), entry_function_name,
                cs_link, f"""<a href="{entry.coverage_report_link}">
                    {entry.source_file}:{entry.branch_line_number}
                </a>"""
            ])
        html_table_string += "</table>"

        return html_table_string
