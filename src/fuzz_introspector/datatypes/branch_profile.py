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
"""Branch profiler"""

import logging
from enum import Enum
from typing import (
    Any,
    Dict,
    List,
    Set,
)

from fuzz_introspector import utils

logger = logging.getLogger(name=__name__)


class BranchSide:
    """Class for representing a branch side."""
    def __init__(self) -> None:
        self.pos = str()
        self.unique_not_covered_complexity = -1
        self.unique_reachable_complexity = -1
        self.reachable_complexity = -1
        self.not_covered_complexity = -1
        self.hitcount = -1
        self.funcs: List[str] = []


class BranchProfile:
    """
    Class for storing information about conditional branches collected by LLVM pass.
    """
    def __init__(self) -> None:
        self.branch_pos = str()
        self.sides: List[BranchSide] = []
        # self.branch_true_side_pos = str()
        # self.branch_false_side_pos = str()
        # self.branch_true_side_unique_not_covered_complexity = -1
        # self.branch_false_side_unique_not_covered_complexity = -1
        # self.branch_true_side_unique_reachable_complexity = -1
        # self.branch_false_side_unique_reachable_complexity = -1
        # self.branch_true_side_reachable_complexity = -1
        # self.branch_false_side_reachable_complexity = -1
        # self.branch_true_side_not_covered_complexity = -1
        # self.branch_false_side_not_covered_complexity = -1
        # self.branch_true_side_hitcount = -1
        # self.branch_false_side_hitcount = -1
        # self.branch_true_side_funcs: List[str] = []
        # self.branch_false_side_funcs: List[str] = []

    def assign_from_yaml_elem(self, elem: Dict[Any, Any]) -> None:
        # This skips the path, as it may cause incosistancy vs coverage file names path
        self.branch_pos = elem['Branch String'].split('/')[-1]
        for br_side_elem in elem['Branch Sides']:
            for idx, br_side in enumerate(br_side_elem):
                if br_side[idx] == 'BranchSide':
                    bs = BranchSide()
                    bs.pos = br_side[idx+1]
                elif br_side[idx] == 'BranchSideFuncs':
                    bs.funcs = utils.load_func_names(br_side[idx+1])
                    self.sides.append(bs)

        # self.branch_true_side_pos = elem['Branch Sides']['TrueSide']
        # self.branch_false_side_pos = elem['Branch Sides']['FalseSide']
        # self.branch_true_side_funcs = utils.load_func_names(elem['Branch Sides']['TrueSideFuncs'])
        # self.branch_false_side_funcs = utils.load_func_names(elem['Branch Sides']['FalseSideFuncs'])

    def assign_from_coverage(self, true_count: str, false_count: str) -> None:
        self.branch_true_side_hitcount = int(true_count)
        self.branch_false_side_hitcount = int(false_count)

    def get_side_unique_reachable_funcnames(self, branch_side: BranchSide) -> Set[str]:
        """Returns the set of unique functions reachable from the specified branch side"""
        true_side_funcs_set = set(self.branch_true_side_funcs)
        false_side_funcs_set = set(self.branch_false_side_funcs)
        if branch_side == BranchSide.TRUE:
            return true_side_funcs_set.difference(false_side_funcs_set)
        return false_side_funcs_set.difference(true_side_funcs_set)

    def dump(self) -> None:
        """
        For debugging purposes, may be removed later.
        """
        print(self.branch_pos, self.branch_true_side_pos, self.branch_false_side_pos,
              self.branch_true_side_reachable_complexity,
              self.branch_false_side_reachable_complexity,
              self.branch_true_side_not_covered_complexity,
              self.branch_false_side_not_covered_complexity,
              self.branch_true_side_hitcount, self.branch_true_side_hitcount)
