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
import json
import pytest
import configparser
import lxml.html

sys.path.append(os.path.dirname(os.path.realpath(__file__)) + "/../../")

from fuzz_introspector import commands, exceptions  # noqa: E402

test_base_dir = os.path.abspath("tests/java")
coverage_link = "random_url"


def retrieve_tag_content(elem):
    content = elem.text
    content = content.replace('\n', '')
    content = content.lstrip(' ').rstrip(' ')
    return content


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
    report_dir = os.path.join(test_base_dir, "result", testcase)

    config_path = os.path.join(test_base_dir, testcase, ".config")
    config = configparser.ConfigParser()
    with open(config_path) as f:
        config.read_string('[test]\n' + f.read())
    class_name = config.get('test', 'entryclass').split(':')
    reached_method = config.get('test', 'reached').split(':')
    unreached_method = config.get('test', 'unreached').split(':')

    os.chdir(report_dir)

    # Ensure testcase report exists
    if not os.path.isdir(report_dir):
        return

    # Run analysis and main logic
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
            coverage_link,
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

    check_essential_files(files, class_name)
    check_calltree_view(files, class_name, report_dir)
    check_analysis_js(report_dir, reached_method, unreached_method)


def check_essential_files(files, class_name):
    """Check if important report files has been generated"""
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


def check_calltree_view(files, class_name, report_dir):
    """Check all calltree_view_*.html"""
    for file in [f for f in files if f.startswith('calltree_view_')]:
        with open(os.path.join(report_dir, file)) as f:
            html = lxml.html.document_fromstring(f.read())

        # Check fuzzer class name
        actual_class = retrieve_tag_content(html.find_class('top-navbar-title')[0])
        actual_class = actual_class.split(' ')[2]
        assert actual_class in class_name

        # Check calltree element line
        elements = html.find_class('coverage-line-inner')
        with open(os.path.join(report_dir, f'fuzzerLogFile-{actual_class}.data')) as f:
            expected_lines = f.readlines()
        assert len(elements) == len(expected_lines) - 1

        # Check first line of call tree
        first_line = elements[0]
        depth = int(retrieve_tag_content(first_line.find_class('node-depth-wrapper')[0]))
        assert depth == 0

        actual_line = retrieve_tag_content(first_line.find_class('language-clike')[0])
        assert actual_line == f"[{actual_class}]." + \
            "fuzzerTestOneInput(com.code_intelligence.jazzer.api.FuzzedDataProvider)"

        # Check last line of call tree
        last_line = elements[len(elements) - 1]
        expected_last_line = expected_lines[len(expected_lines) - 1]
        expected_depth = (len(expected_last_line) - len(expected_last_line.lstrip(' '))) / 2
        actual_depth = int(retrieve_tag_content(last_line.find_class('node-depth-wrapper')[0]))
        assert actual_depth == expected_depth

        actual_line = retrieve_tag_content(last_line.find_class('language-clike')[0])
        expected_line_split = expected_last_line.split(' ')
        assert actual_line == f"[{expected_line_split[-2]}].{expected_line_split[-3]}"

        # Check call site link for the last line
        parent_class = ""
        for element in reversed(elements):
            element_depth = int(retrieve_tag_content(element.find_class('node-depth-wrapper')[0]))
            if (element_depth == actual_depth - 1):
                for link_element in element.find_class('coverage-line-filename')[0].getchildren():
                    if retrieve_tag_content(link_element) == '[function]':
                        parent_class = link_element.get('href')
                        break
                if parent_class != "#":
                    parent_lines = retrieve_tag_content(element.find_class('language-clike')[0])
                    parent_class = parent_lines[1:].split(']')[0]
                    if "." not in parent_class:
                        parent_class = f'default/{parent_class}'
                    else:
                        parent_class = os.sep.join(parent_class.rsplit(".", 1))
                    parent_class = parent_class.split('$')[0]
                break

        actual_link = ""
        for link_element in last_line.find_class('coverage-line-filename')[0].getchildren():
            if retrieve_tag_content(link_element) == '[call site]':
                actual_link = link_element.get('href')
                break
        expected_lineno = expected_line_split[-1].split('=')[1].rstrip('\n')
        if parent_class == "#":
            assert actual_link == "#"
        else:
            assert actual_link == f'{coverage_link}/{parent_class}.java.html#L{expected_lineno}'


def check_analysis_js(report_dir, expected_reached_method, expected_unreached_method):
    """Check the content of the generated analysis_1.js with reachable and unreachable functions"""
    with open(os.path.join(report_dir, 'analysis_1.js')) as f:
        json_list = json.loads(f.read()[22:])

    actual_reached_method = []
    actual_unreached_method = []
    for func in json_list:
        count = int(func['Reached by Fuzzers'].split(' ')[0])
        name = func["Func name"].split('\n')[1].lstrip(' ')
        if count == 0:
            actual_unreached_method.append(name)
        else:
            actual_reached_method.append(name)
    assert actual_reached_method.sort() == expected_reached_method.sort()
    assert actual_unreached_method.sort() == expected_unreached_method.sort()
