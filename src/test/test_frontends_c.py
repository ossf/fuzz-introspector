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
"""Unit testing script for the C frontend"""

from fuzz_introspector.frontends import oss_fuzz  # noqa: E402


def test_simple_sample1():
    project = oss_fuzz.analyse_folder(
        language='c',
        directory='src/test/data/source-code/c/simple-sample-1/',
        entrypoint='LLVMFuzzerTestOneInput',
    )

    functions_reached = project.get_reachable_functions(
        source_code=None,
        function='LLVMFuzzerTestOneInput',
        visited_functions=set())

    assert 'target3' in functions_reached
    assert 'unreached_target3' not in functions_reached

    # Project check
    assert len(project.get_source_codes_with_harnesses()) == 1
