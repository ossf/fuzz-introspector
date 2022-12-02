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

    def assign_from_yaml_elem(self, elem: Dict[Any, Any]) -> None:
        # This skips the path, as it may cause incosistancy vs coverage file names path
        self.branch_pos = elem['Branch String'].split('/')[-1]
        for br_side_elem in elem['Branch Sides']:
            bs = BranchSide()
            bs.pos = br_side_elem['BranchSide']
            bs.funcs = utils.load_func_names(br_side_elem['BranchSideFuncs'])
            self.sides.append(bs)

    def assign_from_coverage(self, counts: List[str]) -> None:
        assert len(counts) <= len(self.sides)
        for idx, count in enumerate(counts):
            self.sides[idx].hitcount = int(count)

    def get_side_unique_reachable_funcnames(self, branch_side_idx: int) -> Set[str]:
        """Returns the set of unique functions reachable from the specified branch side"""
        all_other_sides_funcs = set()
        for idx in range(len(self.sides)):
            if idx == branch_side_idx:
                continue
            all_other_sides_funcs.update(self.sides[idx].funcs)
        wanted_side_funcs = set(self.sides[branch_side_idx].funcs)
        return wanted_side_funcs.difference(all_other_sides_funcs)

    def dump(self) -> None:
        """
        For debugging purposes, may be removed later.
        """

        print(self.branch_pos)
        for side in self.sides:
            print(side.pos, side.unique_reachable_complexity, side.unique_not_covered_complexity,
                  side.reachable_complexity, side.not_covered_complexity, len(side.funcs))
