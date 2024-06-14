# Copyright 2024 Fuzz Introspector Authors
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

import os
import requests

from typing import Optional

BASE_URL = 'https://storage.googleapis.com/oss-fuzz-introspector/{0}/inspector-report/{1}/'
BASE_COVERAGE_URL = 'https://storage.googleapis.com/oss-fuzz-coverage/{0}/reports/{1}/linux/{2}'


def _get_introspector_report_url_base(project_name: str, datestr: str) -> str:
    """Retrieve, format and return the introspector base url"""
    project_url = BASE_URL.format(project_name, datestr.replace("-", ""))
    return project_url


def _get_introspector_report_url_source_base(project_name: str,
                                             datestr: str) -> str:
    """Retrieve, format and return the introspector source base url"""
    return _get_introspector_report_url_base(project_name,
                                             datestr) + "source-code"


def _extract_introspector_raw_source_code(
        project_name: str, date_str: str, target_file: str, is_local: bool,
        local_oss_fuzz: str) -> Optional[str]:
    """Extract and return the raw source code of the target file or return None if not found"""
    if is_local:
        src_location = os.path.join(local_oss_fuzz, 'build', 'out',
                                    project_name, 'inspector',
                                    'source-code') + target_file
        if not os.path.isfile(src_location):
            return None
        with open(src_location, 'r') as f:
            return f.read()

    introspector_summary_url = _get_introspector_report_url_source_base(
        project_name, date_str.replace("-", "")) + target_file

    print("URL: %s" % (introspector_summary_url))
    # Read the introspector atifact
    try:
        raw_source = requests.get(introspector_summary_url, timeout=10).text
    except:
        return None

    return raw_source


def get_introspector_url(project_name: str, datestr: str) -> str:
    """Retrieve, format and return the introspector fuzz report url"""
    return _get_introspector_report_url_base(project_name,
                                             datestr) + "fuzz_report.html"


def get_coverage_report_url(project_name: str, datestr: str,
                            language: str) -> str:
    """Retrieve, format and return the coverage report url for specific project"""
    if language == 'java' or language == 'python' or language == 'go':
        file_report = "index.html"
    else:
        file_report = "report.html"
    project_url = BASE_COVERAGE_URL.format(project_name,
                                           datestr.replace("-", ""),
                                           file_report)
    return project_url


def extract_lines_from_source_code(
        project_name: str,
        date_str: str,
        target_file: str,
        line_begin: int,
        line_end: int,
        is_local: bool,
        local_oss_fuzz: str,
        print_line_numbers: bool = False,
        sanity_check_function_end: bool = False) -> Optional[str]:
    """"Extract and return chosen line of the target source code or return None if not found"""
    raw_source = _extract_introspector_raw_source_code(project_name, date_str,
                                                       target_file, is_local,
                                                       local_oss_fuzz)
    if raw_source is None:
        print("Did not found source")
        return raw_source

    source_lines = raw_source.split("\n")

    return_source = ""

    # Source line numbers start from 1
    line_begin -= 1

    max_length = len(str(line_end))
    function_lines = []
    for line_num in range(line_begin, line_end):
        if line_num >= len(source_lines):
            continue

        if print_line_numbers:
            line_num_str = " " * (max_length - len(str(line_num)))
            return_source += "%s%d " % (line_num_str, line_num)
        return_source += source_lines[line_num] + "\n"
        function_lines.append(source_lines[line_num])

    if sanity_check_function_end:
        found_end_braces = False

        if len(function_lines) > 0:
            if '}' in function_lines[-1]:
                found_end_braces = True
        if not found_end_braces and len(function_lines) > 1:
            if '}' in function_lines[-2] and function_lines[-1].strip() == '':
                found_end_braces = True

        if not found_end_braces:
            # Check the lines after max length
            tmp_ending = ""
            for nl in range(line_end, line_end + 10):
                if nl >= len(source_lines):
                    continue
                tmp_ending += source_lines[nl] + '\n'
                if '{' in source_lines[nl]:
                    break
                if '}' in source_lines[nl]:
                    found_end_braces = True
                    break
            if found_end_braces:
                return_source += tmp_ending

    return return_source
