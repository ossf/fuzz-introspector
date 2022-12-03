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
"""Fuzz JVM report generation routines"""

import os
import sys
import shutil
import pytest
import configparser
import lxml.html

sys.path.append(os.path.dirname(os.path.realpath(__file__)) + "/../../")

from fuzz_introspector import commands, exceptions  # noqa: E402

test_base_dir = os.path.abspath("tests/java")


def retrieve_tag_content(elem):
    content = elem.text
    content = content.replace('\n', '')
    content = content.lstrip(' ').rstrip(' ')
    return content

def prepare_test_project(testcase):
   os.system(f"{test_base_dir}/runTest.sh {testcase}")

@pytest.mark.parametrize(
    "testcase",
    [
        "test1",
        "test2",
        "test3",
        "test4",
        "test5",
        "test6",
        "test7",
        "test8",
        "test9",
        "test10"
    ]
)
def test_full_jvm_report_generation(tmpdir, testcase):
    prepare_test_project(testcase)

    report_dir = os.path.join(test_base_dir, "result", testcase)

    config_path = os.path.join(test_base_dir, testcase, ".config")
    config = configparser.ConfigParser()
    with open(config_path) as f:
        config.read_string('[test]\n' + f.read())
    class_name = config.get('test', 'entryclass').split(':')

    os.chdir(report_dir)

    # Ensure testcase report exists
    if not os.path.isdir(report_dir):
        assert 1 == 2
        return

    # Loop through all callgraph / data files
    for file in [f for f in os.listdir(report_dir) if f.endswith(".data")]:
        # Store path of essential file
        report_cfg_file = os.path.join(report_dir, file)
        report_yaml_file = os.path.join(report_dir, f"{file}.yaml")

        analyses_to_run = [
            "OptimalTargets",
            "RuntimeCoverageAnalysis",
            "FuzzEngineInputAnalysis",
            "FilePathAnalyser",
            "MetadataAnalysis"
        ]

        try:
            commands.run_analysis_on_dir(
                report_dir,
                "random_url",
                analyses_to_run,
                "",
                False,
                "random_name",
                "jvm"
        )
        except exceptions.FuzzIntrospectorError:
            pass

    # Checking starts here
    files = os.listdir(report_dir)

    # First check if important report files has been generated
    expected_files = [
        'all_functions.js',
        'analysis_1.js',
        'calltree.js',
        'clike.js',
        'custom.js',
        'fuzzer_table_data.js',
        'prism.js',
        'fuzz_report.html'
    ]
    for name in class_name:
        expected_files.append(f'{name}_colormap.png')
    for i in range(len(class_name)):
        expected_files.append(f'calltree_view_{i}.html')

    for file in expected_files:
        assert file in files

    # Check all calltree_view_*.html
    for file in [f for f in files if f.startswith('calltree_view_')]:
        with open(os.path.join(report_dir, file)) as f:
            html = lxml.html.document_fromstring(f.read())

        # Check fuzzer class name
        actual_class = retrieve_tag_content(html.find_class('top-navbar-title')[0])
        actual_class = actual_class.split(' ')[2]
        assert actual_class in class_name

        # Check first line of call tree
        for elem in html.find_class('coverage-line-inner'):
            depth = retrieve_tag_content(elem.find_class('node-depth-wrapper')[0])
            if depth == "0":
                actual_line = retrieve_tag_content(elem.find_class('language-clike')[0])
        assert actual_line == f"[{actual_class}]."+\
            "fuzzerTestOneInput(com.code_intelligence.jazzer.api.FuzzedDataProvider)"
