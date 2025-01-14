# Copyright 2025 Fuzz Introspector Authors
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
"""Unit testing script for the Go frontend"""

from fuzz_introspector.frontends import oss_fuzz  # noqa: E402


def test_tree_sitter_go_sample1():
    project = oss_fuzz.analyse_folder(
        'go',
        'src/test/data/source-code/go/test-project-1',
        dump_output=False,
    )

    # Project check
    harness = project.get_source_codes_with_harnesses()
    assert len(harness) == 1

    functions_reached = project.get_reachable_functions(harness[0].source_file, harness[0])

    # Callsite check
    assert 'calculate' in functions_reached
    assert 'fmt.Sprintf' in functions_reached
    assert 'unusedFunction' not in functions_reached


def test_tree_sitter_go_sample2():
    project = oss_fuzz.analyse_folder(
        'go',
        'src/test/data/source-code/go/test-project-2',
        dump_output=False,
    )

    # Project check
    harness = project.get_source_codes_with_harnesses()
    assert len(harness) == 0


def test_tree_sitter_go_sample3():
    project = oss_fuzz.analyse_folder(
        'go',
        'src/test/data/source-code/go/test-project-3',
        dump_output=False,
    )

    # Project check
    harness = project.get_source_codes_with_harnesses()
    assert len(harness) == 0


def test_tree_sitter_go_sample4():
    project = oss_fuzz.analyse_folder(
        'go',
        'src/test/data/source-code/go/test-project-4',
        dump_output=False,
    )

    # Project check
    harness = project.get_source_codes_with_harnesses()
    assert len(harness) == 0


def test_tree_sitter_go_sample5():
    project = oss_fuzz.analyse_folder(
        'go',
        'src/test/data/source-code/go/test-project-5',
        dump_output=False,
    )

    # Project check
    harness = project.get_source_codes_with_harnesses()
    assert len(harness) == 0


def test_tree_sitter_go_sample6():
    project = oss_fuzz.analyse_folder(
        'go',
        'src/test/data/source-code/go/test-project-6',
        dump_output=False,
    )

    # Project check
    harness = project.get_source_codes_with_harnesses()
    assert len(harness) == 0


def test_tree_sitter_go_sample7():
    project = oss_fuzz.analyse_folder(
        'go',
        'src/test/data/source-code/go/test-project-8',
        dump_output=False,
    )

    # Project check
    harness = project.get_source_codes_with_harnesses()
    assert len(harness) == 0


def test_tree_sitter_go_sample8():
    project = oss_fuzz.analyse_folder(
        'go',
        'src/test/data/source-code/go/test-project-8',
        dump_output=False,
    )

    # Project check
    harness = project.get_source_codes_with_harnesses()
    assert len(harness) == 0
