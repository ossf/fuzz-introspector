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
        'Branch Sides': {
            'TrueSide': 'TrueSide',
            'FalseSide': 'FalseSide',
            'TrueSideFuncs': ['abc', 'def', 'ghi'],
            'FalseSideFuncs': ['jkl', 'mno', 'pqr']
        }
    }

    bp.assign_from_yaml_elem(dummy_yaml_elem)

    # Explicitly ensure branch profile is initialized correctly
    assert bp.branch_pos == 'ghi'
    assert bp.branch_true_side_pos == 'TrueSide'
    assert bp.branch_false_side_pos == 'FalseSide'
    assert bp.branch_true_side_reachable_complexity == -1
    assert bp.branch_false_side_reachable_complexity == -1
    assert bp.branch_true_side_not_covered_complexity == -1
    assert bp.branch_false_side_not_covered_complexity == -1
    assert bp.branch_true_side_hitcount == -1
    assert bp.branch_false_side_hitcount == -1
    assert bp.branch_true_side_funcs == ['abc', 'def', 'ghi']
    assert bp.branch_false_side_funcs == ['jkl', 'mno', 'pqr']


def test_branch_profile_assign_from_coverage():
    """Test branch profile initialization from coverage count"""
    bp = branch_profile.BranchProfile()

    bp.assign_from_coverage('123', '456')

    # Explicitly ensure branch profile is initialized correctly
    assert bp.branch_pos == ''
    assert bp.branch_true_side_pos == ''
    assert bp.branch_false_side_pos == ''
    assert bp.branch_true_side_reachable_complexity == -1
    assert bp.branch_false_side_reachable_complexity == -1
    assert bp.branch_true_side_not_covered_complexity == -1
    assert bp.branch_false_side_not_covered_complexity == -1
    assert bp.branch_true_side_hitcount == 123
    assert bp.branch_false_side_hitcount == 456
    assert bp.branch_true_side_funcs == []
    assert bp.branch_false_side_funcs == []


def test_branch_profile_double_assign():
    """Test branch profile initialization with both assign"""
    bp = branch_profile.BranchProfile()

    dummy_yaml_elem = {
        'Branch String': 'abcdefghi',
        'Branch Sides': {
            'TrueSide': 'FalseSide',
            'FalseSide': 'TrueSide',
            'TrueSideFuncs': ['jkl', 'mno', 'pqr'],
            'FalseSideFuncs': ['abc', 'def', 'ghi']
        }
    }

    bp.assign_from_yaml_elem(dummy_yaml_elem)
    bp.assign_from_coverage('456', '123')

    # Explicitly ensure branch profile is initialized correctly
    assert bp.branch_pos == 'abcdefghi'
    assert bp.branch_true_side_pos == 'FalseSide'
    assert bp.branch_false_side_pos == 'TrueSide'
    assert bp.branch_true_side_reachable_complexity == -1
    assert bp.branch_false_side_reachable_complexity == -1
    assert bp.branch_true_side_not_covered_complexity == -1
    assert bp.branch_false_side_not_covered_complexity == -1
    assert bp.branch_true_side_hitcount == 456
    assert bp.branch_false_side_hitcount == 123
    assert bp.branch_true_side_funcs == ['jkl', 'mno', 'pqr']
    assert bp.branch_false_side_funcs == ['abc', 'def', 'ghi']
