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
"""Unit testing script for the Rust frontend"""

from fuzz_introspector.frontends import oss_fuzz  # noqa: E402


def test_tree_sitter_rust_sample1():
    project = oss_fuzz.analyse_folder(
        'rust',
        'src/test/data/source-code/rust/test-project-1',
        dump_output=False,
    )

    # Project check
    harness = project.get_source_codes_with_harnesses()
    assert len(harness) == 1

    functions_reached = project.get_reachable_functions(harness[0].source_file, harness[0])

    # Callsite check
    assert 'and_then' in functions_reached
    assert 'parse::<u32>' in functions_reached
    assert 'factorial' in functions_reached
