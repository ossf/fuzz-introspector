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
"""Test datatypes/bug.py"""

import os
import sys
import pytest

sys.path.append(os.path.dirname(os.path.realpath(__file__)) + "/../")

from fuzz_introspector.datatypes.bug import Bug


def test_bug_initialization():
    """Basic test for bug initialization"""
    bug = Bug(
        "source_file",
        "source_line",
        "function_name",
        "fuzzer_name",
        "description",
        "bug_type"
    )

    # Check initialization
    assert bug.source_file == "source_file"
    assert bug.source_line == "source_line"
    assert bug.function_name == "function_name"
    assert bug.fuzzer_name == "fuzzer_name"
    assert bug.description == "description"
    assert bug.bug_type == "bug_type"
