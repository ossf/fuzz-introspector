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
"""Test datatypes/branch_profile.py"""

import os
import sys

sys.path.append(os.path.dirname(os.path.realpath(__file__)) + "/../")

from fuzz_introspector.datatypes import branch_profile  # noqa: E402


def test_branch_profile_assign_from_yaml_elem():
    """Test branch profile initialization from yaml elem"""
    bp = branch_profile.BranchProfile()

    dummy_yaml_elem = {
        'Branch String': 'abc/def/ghi',
        'Branch Sides': [
            {
                'BranchSide': 'side0_str',
                'BranchSideFuncs': ['abc', 'def', 'ghi']
            },
            {
                'BranchSide': 'side1_str',
                'BranchSideFuncs': ['jkl', 'mno']
            }
        ]
    }

    bp.assign_from_yaml_elem(dummy_yaml_elem)

    # Explicitly ensure branch profile is initialized correctly
    assert len(bp.sides) == 2
    assert bp.branch_pos == 'ghi'
    assert bp.sides[0].pos == 'side0_str'
    assert bp.sides[0].reachable_complexity == -1
    assert bp.sides[0].not_covered_complexity == -1
    assert bp.sides[0].unique_not_covered_complexity == -1
    assert bp.sides[0].unique_reachable_complexity == -1
    assert bp.sides[0].hitcount == -1
    assert bp.sides[0].funcs == ['abc', 'def', 'ghi']
    assert bp.sides[1].pos == 'side1_str'
    assert bp.sides[1].reachable_complexity == -1
    assert bp.sides[1].not_covered_complexity == -1
    assert bp.sides[1].unique_not_covered_complexity == -1
    assert bp.sides[1].unique_reachable_complexity == -1
    assert bp.sides[1].hitcount == -1
    assert bp.sides[1].funcs == ['jkl', 'mno']


def test_branch_profile_double_assign():
    """Test branch profile initialization with both assign"""
    bp = branch_profile.BranchProfile()

    dummy_yaml_elem = {
        'Branch String': 'abc/def/ghi',
        'Branch Sides': [
            {
                'BranchSide': 'side0_str',
                'BranchSideFuncs': ['abc', 'def', 'ghi']
            },
            {
                'BranchSide': 'side1_str',
                'BranchSideFuncs': ['jkl', 'mno']
            }
        ]
    }

    bp.assign_from_yaml_elem(dummy_yaml_elem)
    bp.assign_from_coverage(['456', '123'])

    # Explicitly ensure branch profile is initialized correctly
    assert len(bp.sides) == 2
    assert bp.branch_pos == 'ghi'
    assert bp.sides[0].pos == 'side0_str'
    assert bp.sides[0].reachable_complexity == -1
    assert bp.sides[0].not_covered_complexity == -1
    assert bp.sides[0].unique_not_covered_complexity == -1
    assert bp.sides[0].unique_reachable_complexity == -1
    assert bp.sides[0].hitcount == 456
    assert bp.sides[0].funcs == ['abc', 'def', 'ghi']
    assert bp.sides[1].pos == 'side1_str'
    assert bp.sides[1].reachable_complexity == -1
    assert bp.sides[1].not_covered_complexity == -1
    assert bp.sides[1].unique_not_covered_complexity == -1
    assert bp.sides[1].unique_reachable_complexity == -1
    assert bp.sides[1].hitcount == 123
    assert bp.sides[1].funcs == ['jkl', 'mno']
