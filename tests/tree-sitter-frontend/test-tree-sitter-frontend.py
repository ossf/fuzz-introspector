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
            'cpp/test-project-1': [
                {
                     'name':'LLVMFuzzerTestOneInput',
                     'depth': 0
                },
                {
                     'name':'OuterNamespace::MyClass::memberFunction',
                     'depth': 1
                }
            ]
        }
    }
]

def test_tree_sitter_frontend():
    for testcase in testcases:
        language = testcase.get('language')
        project = testcase.get('project')
        assert language and project

        for dir, sample_list in project.items():
            # Run the tree-sitter-frontend
            calltrees = oss_fuzz.analyse_folder(language, dir, entrypoints.get(language))

            function_depth_map = {}
            for calltree in calltrees:
                for line in calltree.split('\n'):
                    depth = 0
                    while line.startswith("  "):
                        depth += 1
                        line = line[2:]
                    func_name = line.split(' ')[0]
                    function_depth_map[func_name] = depth

            for items in sample_list:
                name = items.get('name')
                depth = items.get('depth')

                assert function_depth_map.get(name) == depth

