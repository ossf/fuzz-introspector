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
"""Module for handling data already processed by OSS-Fuzz."""

import os
import json
import requests
import datetime


def get_date_at_offset_as_str(day_offset=-1):
    datestr = (datetime.date.today() +
               datetime.timedelta(day_offset)).strftime("%Y-%m-%d")
    return datestr


def create_date_range(day_offset, days_to_analyse):
    date_range = []
    range_to_analyse = range(day_offset + days_to_analyse, day_offset, -1)
    for i in range_to_analyse:
        date_range.append(get_date_at_offset_as_str(i * -1))
    return date_range


def create_date_range(day_offset, days_to_analyse):
    date_range = []
    range_to_analyse = range(day_offset + days_to_analyse, day_offset, -1)
    for i in range_to_analyse:
        date_range.append(get_date_at_offset_as_str(i * -1))
    return date_range


def get_introspector_report_url_base(project_name, datestr):
    base_url = 'https://storage.googleapis.com/oss-fuzz-introspector/{0}/inspector-report/{1}/'
    project_url = base_url.format(project_name, datestr)
    return project_url


def get_introspector_report_url_summary(project_name, datestr):
    return get_introspector_report_url_base(project_name,
                                            datestr) + "summary.json"


def get_introspector_report_url_debug_info(project_name, datestr):
    return get_introspector_report_url_base(project_name,
                                            datestr) + "all_debug_info.json"


def get_introspector_report_url_source_base(project_name, datestr):
    return get_introspector_report_url_base(project_name,
                                            datestr) + "source-code"


def extract_introspector_report(project_name, date_str):
    introspector_summary_url = get_introspector_report_url_summary(
        project_name, date_str.replace("-", ""))

    # Read the introspector atifact
    try:
        raw_introspector_json_request = requests.get(introspector_summary_url,
                                                     timeout=10)
    except:
        return None
    try:
        introspector_report = json.loads(raw_introspector_json_request.text)
    except:
        return None

    return introspector_report


def extract_introspector_debug_info(project_name, date_str):
    introspector_summary_url = get_introspector_report_url_debug_info(
        project_name, date_str.replace("-", ""))

    # Read the introspector atifact
    try:
        raw_introspector_json_request = requests.get(introspector_summary_url,
                                                     timeout=10)
    except:
        return None
    try:
        introspector_report = json.loads(raw_introspector_json_request.text)
    except:
        return None

    return introspector_report


def extract_introspector_source_code(project_name, date_str, target_file):
    introspector_summary_url = get_introspector_report_url_source_base(
        project_name, date_str.replace("-", "")) + target_file
    print("Getting: %s" % (introspector_summary_url))

    # Read the introspector atifact
    try:
        raw_source = requests.get(introspector_summary_url, timeout=10).text
    except:
        return None

    return raw_source


def get_source_of_func(funcname, debug_info, project_name, date_str):
    if debug_info is None:
        return
    for k in debug_info:
        print(k)
    for func in debug_info['all_functions_in_project']:
        if func['name'] == funcname:
            print("%s -- {%s:%s}" %
                  (func['name'], func['source']['source_file'],
                   func['source']['source_line']))

            raw_source = extract_introspector_source_code(
                project_name, date_str, func['source']['source_file'])
            if raw_source is None:
                print("Could not get source")
                return
            lines = raw_source.split("\n")
            start_line = int(func['source']['source_line']) - 1
            for idx in range(10):
                print(lines[start_line + idx])


def get_source_of_type(typename, debug_info, project_name, date_str):
    if debug_info is None:
        return
    for k in debug_info:
        print(k)
    for typestruct in debug_info['all_types']:
        if typename in typestruct['name']:
            src_file = os.path.abspath(typestruct['source']['source_file'])
            src_line = int(typestruct['source']['source_line'])
            print("%s -- %s -- %d" % (typestruct['name'], src_file, src_line))
            print(json.dumps(typestruct))

            raw_source = extract_introspector_source_code(
                project_name, date_str, src_file)
            if raw_source is None:
                print("Could not get source")
                return

            lines = raw_source.split("\n")
            start_line = src_line - 10
            for idx in range(20):
                print(lines[start_line + idx])


def get_function_source(project_name, date_str):
    introspector_summary_url = get_introspector_report_url_summary(
        project_name, date_str.replace("-", ""))

    print(introspector_summary_url)
    introspector_report = extract_introspector_report(project_name, date_str)

    introspector_debug_info = extract_introspector_debug_info(
        project_name, date_str)

    if introspector_report is None:
        print("None")
        return

    all_function_list = introspector_report['MergedProjectProfile'][
        'all-functions']
    refined_proj_list = []
    for func in all_function_list:
        refined_proj_list.append({
            'name':
            func['Func name'],
            'code_coverage_url':
            func['func_url'],
            'function_filename':
            func['Functions filename'],
            'runtime_code_coverage':
            float(func['Func lines hit %'].replace("%", "")),
            'is_reached':
            len(func['Reached by Fuzzers']) > 0,
            'reached-by-fuzzers':
            func['Reached by Fuzzers'],
            'project':
            project_name,
            'accumulated_cyclomatic_complexity':
            func['Accumulated cyclomatic complexity'],
            'llvm-instruction-count':
            func['I Count'],
            'undiscovered-complexity':
            func['Undiscovered complexity'],
            'function-arguments':
            func['Args'],
            'function-argument-names':
            func.get('ArgNames', ['Did not find arguments']),
            'return-type':
            func.get('return_type', 'N/A'),
            'raw-function-name':
            func.get('raw-function-name', 'N/A'),
            'date-str':
            date_str
        })

    get_source_of_type('auth_token', introspector_debug_info, project_name,
                       date_str)
    get_source_of_func('cram_gamma_decode_init', introspector_debug_info,
                       project_name, date_str)


def main():
    day_range = create_date_range(-1, 1)
    get_function_source("htslib", day_range[0])


if __name__ == "__main__":
    main()
