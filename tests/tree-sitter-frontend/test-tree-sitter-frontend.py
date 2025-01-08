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
                'fuzzerLogFile-sample.data'
            ]
        }
    }
]

def test_tree_sitter_frontend():
    for testcase in testcases:
        language = testcase.get('language')
        project = testcase.get('project')
        assert language and project

        for dir, output in project.items():
            # Run the tree-sitter-frontend
            oss_fuzz.analyse_folder(language, dir, entrypoints.get(language))

            # Check if data and data.yaml is generated correctly
            for file in output:
                assert os.path.isfile(file)

                check_data_file(file, os.path.join(dir, file))
                check_data_yaml_file(f'{file}.yaml', os.path.join(dir, f'{file}.yaml'))


def check_data_file(output, expected):
    output_map = process_data_file(output)
    expected_map = process_data_file(expected)

    assert output_map
    assert expected_map
    assert output_map == expected_map


def check_data_yaml_file(output, expected):
    output_map = process_data_yaml_file(output)
    expected_map = process_data_yaml_file(expected)

    assert output_map
    assert expected_map
    assert output_map == expected_map


def process_data_file(file):
    data_map = {}
    content = []
    with open(file, 'r') as f:
        content = f.readlines()[1:]

    for line in content:
        depth = 0
        while line.startswith("  "):
            depth += 1
            line = line[2:]
        lines = data_map.get(depth, [])
        lines.append(line.strip())
        data_map[depth] = sorted(lines)

    return data_map


def process_data_yaml_file(file):
    def _sort(obj):
        if isinstance(obj, dict):
            return {key: _sort(value) for key, value in sorted(obj.items())}
        elif isinstance(obj, list):
            return sorted((_sort(item) for item in obj), key=lambda x: str(x))
        else:
            return obj

    content = None
    with open(file, 'r') as f:
        content = yaml.safe_load(f)

    if content:
        return _sort(content)

    return None

