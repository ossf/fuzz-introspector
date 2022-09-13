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
import json

from typing import (
    Dict,
    List,
    Tuple,
    Optional,
    Set,
)

from fuzz_introspector import analysis
from fuzz_introspector import utils
from fuzz_introspector import cfg_load
from fuzz_introspector import html_helpers
from fuzz_introspector.datatypes import project_profile, fuzzer_profile

# For pretty printing the html code:
from bs4 import BeautifulSoup as bs

logger = logging.getLogger(name=__name__)


class Analysis(analysis.AnalysisInterface):
    def __init__(self) -> None:
        logger.info("Creating FuzzCalltreeAnalysis")

    @staticmethod
    def get_name():
        return "FuzzCalltreeAnalysis"

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
        Creates the HTML of the calltree. Returns the HTML as a string.
        """
        logger.info("Not implemented")
        return ""

    def create_calltree(self, profile: fuzzer_profile.FuzzerProfile) -> str:
        logger.info("In calltree")
        # Generate HTML for the calltree
        calltree_html_string = "<h1>Fuzzer calltree</h1>"
        calltree_html_string += "<div id=\"calltree-wrapper\">"
        calltree_html_string += "<div class='call-tree-section-wrapper'>"
        nodes = cfg_load.extract_all_callsites(profile.function_call_depths)
        for i in range(len(nodes)):
            node = nodes[i]

            demangled_name = utils.demangle_cpp_func(node.dst_function_name)
            # We may not want to show certain functions at times, e.g. libc functions
            # in case it bloats the calltree
            # libc_funcs = { "free" }
            libc_funcs: Set[str] = set()
            avoid = len([fn for fn in libc_funcs if fn in demangled_name]) > 0
            if avoid:
                continue

            # Prepare strings needed in the HTML
            color_to_be = node.cov_color
            callsite_link = node.cov_callsite_link
            link = node.cov_link
            ct_idx_str = self.create_str_node_ctx_idx(str(node.cov_ct_idx))

            # Only display [function] link if we have, otherwhise show no [function] text.
            if node.dst_function_source_file.replace(" ", "") != "":
                func_href = f"""<a href="{link}">[function]</a>"""
            else:
                func_href = ""

            # indentation in html:
            indentation = "%dpx" % (int(node.depth) * 16 + 100)

            if i > 0:
                previous_node = nodes[i - 1]
                if previous_node.depth == node.depth:
                    calltree_html_string += "</div>"
                depth_diff = previous_node.depth - node.depth
                if depth_diff >= 1:
                    closing_divs = "</div>"  # To close "calltree-line-wrapper"
                    closing_divs = "</div>" * (int(depth_diff) + 1)
                    calltree_html_string += closing_divs

            calltree_html_string += f"""
    <div class="{color_to_be}-background coverage-line">
        <span class="coverage-line-inner" data-calltree-idx="{ct_idx_str}"
        data-paddingleft="{indentation}" style="padding-left: {indentation}">
            <span class="node-depth-wrapper">{node.depth}</span>
            <code class="language-clike">
                {demangled_name}
            </code>
            <span class="coverage-line-filename">
                {func_href}
                <a href="{callsite_link}">
                    [call site2]
                </a>
                <span class="calltree-idx">{ct_idx_str}</span>
            </span>
        </span>
        """
            if i != len(nodes) - 1:
                next_node = nodes[i + 1]
                if next_node.depth > node.depth:
                    calltree_html_string += f"""<div
        class="calltree-line-wrapper open level-{int(node.depth)}"
         data-paddingleft="{indentation}" >"""
                elif next_node.depth < node.depth:
                    depth_diff = int(node.depth - next_node.depth)
                    calltree_html_string += "</div>" * depth_diff

        calltree_html_string += "</div>"
        logger.info("Calltree created")

        # Write the HTML to a file called calltree_view_XX.html where XX is a counter.
        calltree_file_idx = 0
        calltree_html_file = f"calltree_view_{calltree_file_idx}.html"
        while os.path.isfile(calltree_html_file):
            calltree_file_idx += 1
            calltree_html_file = f"calltree_view_{calltree_file_idx}.html"

        self.html_create_dedicated_calltree_file(
            calltree_html_string,
            calltree_html_file,
            profile,
        )
        return calltree_html_file

    def collect_calltree_nodes(self, branch_blockers: List[analysis.FuzzBranchBlocker],
                               func_call_depth: Optional[cfg_load.CalltreeCallsite]
                               ) -> Dict[analysis.FuzzBranchBlocker, cfg_load.CalltreeCallsite]:
        """Map branch blockers to the calltree nodes"""

        all_callsites = cfg_load.extract_all_callsites(func_call_depth)
        nodes_num = len(all_callsites)
        if nodes_num == 0:
            logger.error("Failed to extract callsites, "
                         "the blocker table won't have correct links to calltree.")

        blocker_node_map: Dict[analysis.FuzzBranchBlocker, cfg_load.CalltreeCallsite] = dict()
        for blocker in branch_blockers:
            func_name = blocker.function_name
            branch_linenumber = int(blocker.branch_line_number)
            for idx, node in enumerate(all_callsites):
                if func_name == node.dst_function_name:
                    depth = node.depth + 1
                    found_node = node
                    # Try to adjust the blocker node in the callees of current func
                    for i in range(idx + 1, nodes_num):
                        new_node = all_callsites[i]
                        if depth > new_node.depth:
                            break  # Reached the caller of the node
                        if depth == new_node.depth and branch_linenumber >= new_node.src_linenumber:
                            found_node = new_node
                    blocker_node_map[blocker] = found_node
                    break

        return blocker_node_map

    def html_create_dedicated_calltree_file(
        self,
        calltree_html_string: str,
        filename: str,
        profile: fuzzer_profile.FuzzerProfile
    ) -> None:
        """
        Write a wrapped HTML file with the tags needed from fuzz-introspector
        We use this only for wrapping calltrees at the moment, however, down
        the line it makes sense to have an easy wrapper for other HTML pages too.
        """
        complete_html_string = ""
        blocker_infos = {}
        # HTML start
        html_header = html_helpers.html_get_header(
            calltree=True,
            title=f"Fuzz introspector: { profile.identifier }"
        )
        html_header += '<div class="content-section calltree-content-section">'
        complete_html_string += html_header

        # Display fuzz blocker at top of page
        if profile.branch_blockers:
            blockers_node_map = self.collect_calltree_nodes(profile.branch_blockers[:12],
                                                            profile.function_call_depths)
            # Record the link to coverage report for the branch blocker.
            for b_blocker, ct_node in blockers_node_map.items():
                idx = self.create_str_node_ctx_idx(str(ct_node.cov_ct_idx))
                blocker_infos[idx] = b_blocker.coverage_report_link

            fuzz_blocker_table = self.create_branch_blocker_table(
                profile,
                [],
                "",
                12
            )
        else:
            fuzz_blocker_nodes = self.get_fuzz_blockers(
                profile,
                max_blockers_to_extract=12
            )

            fuzz_blocker_table = self.create_fuzz_blocker_table(
                profile,
                [],
                "",
                fuzz_blockers=fuzz_blocker_nodes
            )

            for node in fuzz_blocker_nodes:
                # The link to coverage report is not present in this type of blockers.
                blocker_infos[self.create_str_node_ctx_idx(str(node.cov_ct_idx))] = ""

        if fuzz_blocker_table is not None:
            complete_html_string += "<div class=\"report-box\">"
            complete_html_string += "<h1>Fuzz blockers</h1>"
            complete_html_string += fuzz_blocker_table
            complete_html_string += "</div>"

        # Display calltree
        complete_html_string += calltree_html_string
        complete_html_string += "</div></div></div></div></div>"
        complete_html_string += "<div id=\"side-overview-wrapper\"></div>"

        # HTML end
        html_end = '</div>'
        # blocker_idxs = []
        # for node in fuzz_blocker_nodes:
        #     blocker_idxs.append(self.create_str_node_ctx_idx(str(node.cov_ct_idx)))

        if len(blocker_infos) > 0:
            html_end = "<script>"
            html_end += f'var fuzz_blocker_infos = \'{json.dumps(blocker_infos)}\';'
            html_end += "</script>"

        html_end += "<script src=\"calltree.js\"></script>"
        complete_html_string += html_end

        complete_html_string += "</body></html>"

        # Beautify and write HTML
        soup = bs(complete_html_string, "html.parser")
        pretty_html = soup.prettify()
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
        blocker_list: List[cfg_load.CalltreeCallsite] = list()

        # Extract all callsites in calltree and exit early if none
        all_callsites = cfg_load.extract_all_callsites(profile.function_call_depths)
        if len(all_callsites) == 0:
            return blocker_list

        # Filter nodes that has forward reds. Extract maximum max_blockers_to_extract nodes.
        nodes_sorted_by_red_ahead = sorted(all_callsites,
                                           key=lambda x: x.cov_forward_reds,
                                           reverse=True)
        for node in nodes_sorted_by_red_ahead:
            if node.cov_forward_reds == 0 or len(blocker_list) >= max_blockers_to_extract:
                break
            blocker_list.append(node)
        return blocker_list

    def create_fuzz_blocker_table(
        self,
        profile: fuzzer_profile.FuzzerProfile,
        tables: List[str],
        calltree_file_name: str,
        fuzz_blockers: Optional[List[cfg_load.CalltreeCallsite]] = None,
        file_link: Optional[str] = None
    ) -> Optional[str]:
        """
        Creates HTML string for table showing fuzz blockers.
        """
        logger.info("Creating fuzz blocker table")

        # Get the fuzz blockers
        if fuzz_blockers is None:
            fuzz_blockers = self.get_fuzz_blockers(
                profile,
                max_blockers_to_extract=12
            )
        if len(fuzz_blockers) == 0:
            return None

        html_table_string = "<p class='no-top-margin'>The followings nodes " \
                            "represent call sites where fuzz blockers occur.</p>"
        tables.append(f"myTable{len(tables)}")
        html_table_string += html_helpers.html_create_table_head(
            tables[-1],
            [
                ("Amount of callsites blocked",
                 "Total amount of callsites blocked"),
                ("Calltree index",
                 "Index in call tree where the fuzz blocker is."),
                ("Parent function",
                 "Function in which the call site that blocks resides."),
                ("Callsite",
                 ""),
                ("Largest blocked function",
                 "This is the function with highest cyclomatiic complexity amongst"
                 "all of the functions that are blocked. As such, it's a way of "
                 "highlighting a potentially important function being blocked")
            ],
            sort_by_column=0,
            sort_order="desc"
        )
        for node in fuzz_blockers:
            link_prefix = "0" * (5 - len(str(node.cov_ct_idx)))
            node_id = "%s%s" % (link_prefix, node.cov_ct_idx)
            if file_link is not None:
                cs_link = (
                    "<span class=\"text-link\">"
                    f"<a href=\"{file_link}?scrollToNode={node_id}\">call site"
                    "</a></span>"
                )
            else:
                cs_link = (
                    "<span class=\"text-link\" "
                    f"onclick=\" scrollToNodeInCT('{node_id}')\">"
                    "call site</span>"
                )
            html_table_string += html_helpers.html_table_add_row([
                str(node.cov_forward_reds),
                str(node.cov_ct_idx),
                node.cov_parent,
                cs_link,
                node.cov_largest_blocked_func
            ])
        html_table_string += "</table>"

        return html_table_string

    def create_branch_blocker_table(
        self,
        profile: fuzzer_profile.FuzzerProfile,
        tables: List[str],
        file_link: str,
        max_number_of_blockers: int
    ) -> Optional[str]:
        """
        Creates HTML string for table showing branch blockers.
        """
        logger.info("Creating branch blocker table")

        branch_blockers = profile.branch_blockers[:max_number_of_blockers]
        if len(branch_blockers) == 0:
            return None

        blockers_node_map = self.collect_calltree_nodes(branch_blockers,
                                                        profile.function_call_depths)

        html_table_string = "<p class='no-top-margin'>The followings are " \
                            "the branches where fuzzer fails to bypass.</p>"
        tables.append(f"myTable{len(tables)}")
        html_table_string += html_helpers.html_create_table_head(
            tables[-1],
            [
                ("Blocked Complexity",
                 "Cyclomatic Complexity that is not covered because of blockage."),
                ("Reachable Complexity",
                 "Cyclomatic Complexity that the blocked branch-side can reach."),
                ("Function Name",
                 "Function containing the blocked branch."),
                ("Function Callsite", "The blocking function callsite in the calltree"),
                ("Blocked Branch", "The line of code correspoinding to the blocked branch"),
            ],
            sort_by_column=0,
            sort_order="desc"
        )
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
                    f"<a href=\"{file_link}?scrollToNode={node_id}\">call site"
                    "</a></span>"
                )
            else:
                cs_link = (
                    "<span class=\"text-link\" "
                    f"onclick=\" scrollToNodeInCT('{node_id}')\">"
                    "call site</span>"
                )

            html_table_string += html_helpers.html_table_add_row([
                str(entry.blocked_not_covered_complexity),
                str(entry.blocked_reachable_complexity),
                utils.demangle_cpp_func(entry.function_name),
                cs_link,
                f"""<a href="{entry.coverage_report_link}">
                    {entry.source_file}:{entry.branch_line_number}
                </a>"""
            ])
        html_table_string += "</table>"

        return html_table_string
