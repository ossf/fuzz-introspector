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
"""Unit testing script for tree-sitter-frontend."""

import os
import sys
import pytest
import yaml

sys.path.append(os.path.dirname(os.path.realpath(__file__)) + "/../../")

from fuzz_introspector.frontends import oss_fuzz  # noqa: E402

entrypoints = {
    'c': 'LLVMFuzzerTestOneInput',
    'c++': 'LLVMFuzzerTestOneInput',
    'go': '',
    'rust': 'fuzz_target',
    'jvm': 'fuzzerTestOneInput'
}

testcases = [
    {
        'language': 'c++',
        'project': {
            'cpp/test-project-1': {
                 'count': 6,
                 'reaches': '    isPositive'
            }
        }
    }
]

def test_tree_sitter_frontend():
    for testcase in testcases:
        language = testcase.get('language')
        project = testcase.get('project')

        for dir, sample_map in project.items():
            calltrees = oss_fuzz.analyse_folder(language, dir, entrypoints.get(language))

            found = False
            for calltree in calltrees:
                count = sample_map['count']
                reaches = sample_map['reaches']
                lines = calltree.split('\n')

                if len(lines) == count and reaches in calltree:
                    found = True

            assert found
