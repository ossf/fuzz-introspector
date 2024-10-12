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
""" Module for loading CFG files """

import logging

from typing import (List, Optional)

from fuzz_introspector.exceptions import CalltreeError

logger = logging.getLogger(name=__name__)


class CalltreeCallsite():
    """
    Represents a single node in the calltree
    """

    def __init__(
            self, dst_function_name: str, dst_function_source_file: str,
            depth: int, src_linenumber: int,
            parent_calltree_callsite: Optional['CalltreeCallsite']) -> None:

        # Destination information
        self.dst_function_name: str = dst_function_name
        self.dst_function_source_file: str = dst_function_source_file
        self.src_linenumber: int = src_linenumber
        self.parent_calltree_callsite: Optional[
            CalltreeCallsite] = parent_calltree_callsite
        self.depth = depth
        self.src_function_source_file: Optional[str] = None
        self.src_function_name: Optional[str] = None
        self.children: List[CalltreeCallsite] = []
        self.cov_ct_idx: int = -1
        self.cov_parent: str = ""
        self.cov_hitcount: int = -1
        self.cov_color: str = ""
        self.hitcount = 0
        self.cov_link: str = ""
        self.cov_callsite_link: str = ""
        self.cov_forward_reds: int = -1
        self.cov_largest_blocked_func: str = ""


def extract_all_callsites_recursive(
        calltree: CalltreeCallsite,
        callsite_nodes: List[CalltreeCallsite]) -> None:
    """
    Given a node, will assemble all callsites in the children. Recursive function.
    """
    callsite_nodes.append(calltree)
    for c in calltree.children:
        extract_all_callsites_recursive(c, callsite_nodes)


def extract_all_callsites(
        calltree: Optional[CalltreeCallsite]) -> List[CalltreeCallsite]:
    if calltree is None:
        logger.error("Trying to extract from a None calltree")
        return []

    cs_list: List[CalltreeCallsite] = []
    extract_all_callsites_recursive(calltree, cs_list)
    return cs_list


def print_ctcs_tree(ctcs: CalltreeCallsite) -> None:
    spacing = " " * int(ctcs.depth)
    print(f"{spacing}{ctcs.dst_function_name}"
          f" -- {ctcs.dst_function_source_file} -- {ctcs.src_linenumber}")
    for c in ctcs.children:
        print_ctcs_tree(c)


def data_file_read_calltree(filename: str) -> Optional[CalltreeCallsite]:
    """
    Extracts the calltree of a fuzzer from a .data file.
    This is for C/C++ files

    Returns a CalltreeCallsite that is the root of the tree read.
    """
    read_tree = False
    curr_ctcs_node = None
    curr_depth = -1
    with open(filename, "r") as flog:
        # Read in all lines catching decode errors
        all_lines = []
        try:
            for line in flog:
                all_lines.append(line)
        except UnicodeDecodeError:
            raise CalltreeError("Decoding error when reading CFG file")

        for line in all_lines:
            line = line.replace("\n", "")
            if read_tree and "======" not in line:
                stripped_line = line.strip().split(" ")
                # Parse the line
                # Type: {spacing depth} {target filename} {line count}
                if len(stripped_line) == 3:
                    target_func = stripped_line[0]
                    filename = stripped_line[1]
                    linenumber = int(stripped_line[2].replace(
                        "linenumber=", ""))
                else:
                    target_func = stripped_line[0]
                    filename = ""
                    linenumber = 0

                if "......" in filename or "......" in target_func:
                    filename = filename.replace("......", "")
                    target_func = target_func.replace("......", "")

                space_count = len(line) - len(line.lstrip(' '))
                depth = int(space_count / 2)

                # Create a callsite nide
                ctcs = CalltreeCallsite(target_func, filename, depth,
                                        linenumber, curr_ctcs_node)

                # Check if this node is still a child of the current parent node and handle if not.
                if curr_depth == -1:
                    # First node
                    curr_ctcs_node = ctcs
                elif depth > curr_depth and curr_ctcs_node is not None:
                    # We are going one calldepth deeper
                    # Special case in the root parent case, where we have no parent in the current
                    # node
                    # and also no children.
                    if (curr_ctcs_node.parent_calltree_callsite is None
                            and len(curr_ctcs_node.children) == 0):
                        None
                    else:
                        curr_ctcs_node = curr_ctcs_node.children[-1]

                elif depth < curr_depth and curr_ctcs_node is not None:
                    # We are going up, find out how much
                    depth_diff = int(curr_depth - depth)
                    tmp_node = curr_ctcs_node
                    idx = 0
                    while idx < depth_diff and tmp_node.parent_calltree_callsite is not None:
                        tmp_node = tmp_node.parent_calltree_callsite
                        idx += 1
                    curr_ctcs_node = tmp_node
                # Add the node to the current parent
                if curr_depth != -1 and curr_ctcs_node is not None:
                    ctcs.parent_calltree_callsite = curr_ctcs_node
                    ctcs.src_function_name = ctcs.parent_calltree_callsite.dst_function_name
                    curr_ctcs_node.children.append(ctcs)
                curr_depth = depth

            if "====================================" in line:
                read_tree = False
            if "Call tree" in line:
                read_tree = True

    # move upwards from any node in the tree
    ctcs_root: Optional[CalltreeCallsite] = curr_ctcs_node
    if ctcs_root is None:
        return None
    while ctcs_root.depth != 0:
        ctcs_root = ctcs_root.parent_calltree_callsite
        if ctcs_root is None:
            return None
    # print_ctcs_tree(ctcs_root)
    return ctcs_root
