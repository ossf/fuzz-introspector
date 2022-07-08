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
import os
import sys
import pytest

sys.path.append(os.path.dirname(os.path.realpath(__file__)) + "/../")

from fuzz_introspector import utils  # noqa: E402


@pytest.mark.parametrize(
    ("s1", "should_change"),
    [
        ("willnotnormalise", False),
        ("ksnfksjdgj", False),
        ("randomstring", False),
        ("this should change", True),
        ("This\tShuold\nAlso\nchange", True),
        ("should\tchange", True)
    ]
)
def test_normalise_str(s1: str, should_change: bool):
    changed = utils.normalise_str(s1) != s1
    assert changed == should_change


@pytest.mark.parametrize(
    ("strs", "expected"),
    [
        (
            [
                "the_prefix_a",
                "the_prefix_b",
                "the_prefix_c"
            ],
            "the_prefix_"
        ),
        (
            [
                "/src/project_name/file1.c",
                "/src/project_name/file2.c",
                "/src/project_name/README.md",
            ],
            "/src/project_name/"
        )
    ]
)
def test_longest_common_prefix(strs: str, expected: str):
    longest_prefix = utils.longest_common_prefix(strs)
    assert longest_prefix == expected
