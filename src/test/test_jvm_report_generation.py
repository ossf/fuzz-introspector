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
import shutil
import configparser
import lxml.html

sys.path.append(os.path.dirname(os.path.realpath(__file__)) + "/../../")

from fuzz_introspector import commands, constants  # noqa: E402

base_dir = os.path.abspath(".")
test_base_dir = os.path.join(base_dir, "tests/java")
coverage_link = "random_url"
project_name = "random_name"


def safe_split(string, sep):
    if string == "":
        return []
    else:
        return string.split(sep)


def retrieve_tag_content(elem):
    content = elem.text
    content = content.replace('\n', '')
    content = content.lstrip(' ').rstrip(' ')
    return content


def process_mapping(map_str):
    result = dict()
    for item in map_str.split(';'):
        split = item.split(':')
        result_list = []
        if split[1] != "[]":
            for value in split[1].strip('[]').split(','):
                result_list.append(value)
        result[split[0]] = result_list

    return result


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
    result_dir = os.path.join(test_base_dir, "result", testcase)

    config_path = os.path.join(test_base_dir, testcase, ".config")
    config = configparser.ConfigParser()
    with open(config_path) as f:
        config.read_string('[test]\n' + f.read())
    class_name = config.get('test', 'entryclass').split(':')
    optimal_reached = safe_split(config.get('test', 'optimalreached'), ":")
    optimal_unreached = safe_split(config.get('test', 'optimalunreached'), ":")
    reached = safe_split(config.get('test', 'reached'), ":")
    unreached = safe_split(config.get('test', 'unreached'), ":")
    files_reached = process_mapping(config.get('test', 'filereached'))
    files_covered = process_mapping(config.get('test', 'filecovered'))

    for file in os.listdir(result_dir):
        shutil.copy(os.path.join(result_dir, file), tmpdir)

    os.mkdir(os.path.join(tmpdir, coverage_link))
    shutil.copy(
        os.path.join(test_base_dir, testcase, "sample-jacoco.xml"),
        os.path.join(tmpdir, coverage_link)
    )

    os.chdir(tmpdir)

    # Run analysis and main logic
    analyses_to_run = [
        "OptimalTargets",
        "RuntimeCoverageAnalysis",
        "FuzzEngineInputAnalysis",
        "FilePathAnalyser",
        "MetadataAnalysis"
    ]

    assert commands.run_analysis_on_dir(
        tmpdir,
        coverage_link,
        analyses_to_run,
        "",
        False,
        project_name,
        "jvm"
    ) == constants.APP_EXIT_SUCCESS

    # Checking starts here
    files = os.listdir(tmpdir)

    check_essential_files(files, class_name)
    check_calltree_view(tmpdir, files, class_name)
    check_function_list(tmpdir, optimal_reached, optimal_unreached, 'analysis_1.js')
    check_function_list(tmpdir, reached, unreached, 'all_functions.js')
    check_fuzz_report(tmpdir, class_name, files_reached, files_covered, reached, unreached)

    os.chdir(base_dir)


def check_essential_files(files, class_name):
    """Check if important report files has been generated
       Ignoring all the styling js and css files"""
    expected_files = [
        'all_functions.js',
        'analysis_1.js',
        'fuzzer_table_data.js',
        'fuzz_report.html'
    ]
    for name in class_name:
        expected_files.append(f'{name}_colormap.png')
    for i in range(len(class_name)):
        expected_files.append(f'calltree_view_{i}.html')

    for file in expected_files:
        assert file in files


def check_calltree_view(report_dir, files, class_name):
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


def check_function_list(report_dir, expected_reached_method, expected_unreached_method, file):
    """Check the content of the generated function list in all_function.js
       or analysis_1.js with reachable and unreachable functions. They have
       almost the same structure, only analysis_1.js contains a optimal
       subset of functions as a result of an analysis."""
    with open(os.path.join(report_dir, file)) as f:
        json_list = json.loads("".join(f.read().split('=')[1:]))

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


def check_fuzz_report(
    report_dir,
    class_name,
    files_reached,
    files_covered,
    func_reached,
    func_unreached
):
    """Check main fuzz_report.html"""
    with open(os.path.join(report_dir, 'fuzz_report.html')) as f:
        html = lxml.html.document_fromstring(f.read())

    # Check fuzzer class name
    for item in html.find_class('pfc-list-item'):
        actual_class = retrieve_tag_content(item)
    assert actual_class in class_name

    # Check project name
    item = html.find_class('left-sidebar-content-box')[1].getchildren()[1]
    actual_project_name = retrieve_tag_content(item.getchildren()[0])
    assert actual_project_name == f'Project overview: {project_name}'

    # Check fuzzer name
    counter = 7
    for i in range(len(class_name)):
        item = html.find_class('left-sidebar-content-box')[1].getchildren()[counter + i * 2]
        actual_name = retrieve_tag_content(item.getchildren()[0])
        actual_name_link = item.getchildren()[0].get('href')
        assert actual_name.split(' ')[1] in class_name
        assert actual_name_link.split('-')[1] in class_name

    # Check static coverage
    item_list = html.find_class('report-box mt-0')
    for item in item_list:
        if retrieve_tag_content(item.getchildren()[0]).startswith("Functions"):
            count_str = retrieve_tag_content(item.getchildren()[2])
            actual_reached_count = int(count_str.split("/")[0])
            actual_total_count = int(count_str.split("/")[1])
            assert len(func_reached) == actual_reached_count
            assert (len(func_reached) + len(func_unreached)) == actual_total_count

    # Check files in report
    item = html.find_class('report-box')[11].find_class('cell-border compact stripe')[0]
    tbody = item.getchildren()[1]
    for tr in tbody.getchildren():
        td_list = tr.getchildren()
        actual_file = retrieve_tag_content(td_list[0])
        actual_reached = [item for item in retrieve_tag_content(td_list[1]).strip('[]').split(', ')]
        actual_covered = [item for item in retrieve_tag_content(td_list[2]).strip('[]').split(', ')]
        assert actual_file in files_reached
        assert actual_file in files_covered
        assert files_reached[actual_file].sort() == actual_reached.sort()
        assert files_covered[actual_file].sort() == actual_covered.sort()

    # Check metadata
    item = html.find_class('report-box')[12].find_class('cell-border compact stripe')[0]
    tbody = item.getchildren()[1]
    for tr in tbody.getchildren():
        td_list = tr.getchildren()
        fuzzer = retrieve_tag_content(td_list[0])
        fuzzer_data = retrieve_tag_content(td_list[1].getchildren()[0])
        fuzzer_data_link = td_list[1].getchildren()[0].get('href')
        fuzzer_yaml = retrieve_tag_content(td_list[2].getchildren()[0])
        fuzzer_yaml_link = td_list[2].getchildren()[0].get('href')
        assert fuzzer in class_name
        assert fuzzer_data == f'fuzzerLogFile-{fuzzer}.data'
        assert fuzzer_data == fuzzer_data_link
        assert fuzzer_yaml == f'fuzzerLogFile-{fuzzer}.data.yaml'
        assert fuzzer_yaml == fuzzer_yaml_link
