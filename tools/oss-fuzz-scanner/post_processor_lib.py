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

    #print("Getting: %s" % (introspector_summary_url))

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
    #print("Getting: %s" % (introspector_summary_url))

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


def extract_introspector_raw_source_code(project_name, date_str, target_file):
    introspector_summary_url = get_introspector_report_url_source_base(
        project_name, date_str.replace("-", "")) + target_file
    #print("Getting: %s" % (introspector_summary_url))

    # Read the introspector atifact
    try:
        raw_source = requests.get(introspector_summary_url, timeout=10).text
    except:
        return None

    return raw_source


def extract_lines_from_source_code(project_name,
                                   date_str,
                                   target_file,
                                   line_begin,
                                   line_end,
                                   print_line_numbers=True):
    raw_source = extract_introspector_raw_source_code(project_name, date_str,
                                                      target_file)
    if raw_source is None:
        return raw_source

    source_lines = raw_source.split("\n")

    return_source = ""
    max_length = len(str(line_end))
    for line_num in range(line_begin, line_end):
        if line_num >= len(source_lines):
            continue

        if print_line_numbers:
            line_num_str = " " * (max_length - len(str(line_num)))
            return_source += "%s%d " % (line_num_str, line_num)
        return_source += source_lines[line_num] + "\n"
    return return_source


def get_source_of_func(funcname, debug_info, project_name, date_str):
    if debug_info is None:
        return
    for func in debug_info['all_functions_in_project']:
        if func['name'] == funcname:
            print("%s -- {%s:%s}" %
                  (func['name'], func['source']['source_file'],
                   func['source']['source_line']))

            function_line = int(func['source']['source_line']) - 1
            src_file = func['source']['source_file']
            function_source = extract_lines_from_source_code(
                project_name, date_str, src_file, function_line,
                function_line + 30)
            return function_source
    return None


def get_source_of_type(typename, debug_info, project_name, date_str):
    if debug_info is None:
        return
    for typestruct in debug_info['all_types']:
        if typename in typestruct['name']:
            src_file = os.path.abspath(typestruct['source']['source_file'])
            src_line = int(typestruct['source']['source_line'])
            print("Type source location: %s : %d" % (src_file, src_line))
            type_source = extract_lines_from_source_code(
                project_name, date_str, src_file, src_line - 10, src_line + 10)
            print(type_source)


def print_all_cross_references_to_function(target_func, all_function_list,
                                           project_name, date_str):
    print("Cross-references for %s" % (target_func))
    all_funcs = []
    all_xrefs = set()
    for func in all_function_list:
        to_add = False
        for callsite_dst in func['callsites']:
            if callsite_dst == target_func:
                # key vaues pairs, the key is a string the value is list
                all_xrefs.add(func['Func name'])
                to_add = True
        if to_add:
            all_funcs.append(func)

    #for xref in all_xrefs:
    #    print("- %s"%(xref))
    for func in all_funcs:
        print("xref {%s --> %s}" % (func['Func name'], target_func))
        for callsite_dst in func['callsites']:
            if callsite_dst == target_func:
                all_locations = func['callsites'][callsite_dst]
                for loc in all_locations:
                    filename = loc.split('#')[0]
                    cs_linenumber = int(loc.split(':')[-1])

                    print("xref location of callsite source: %s : %d" %
                          (func['Functions filename'], int(cs_linenumber)))
                    target_file = func['Functions filename']

                    print("xref source code of area surrounding callsite:")
                    source_code = extract_lines_from_source_code(
                        project_name, date_str, target_file, cs_linenumber - 2,
                        cs_linenumber + 2)
                    print(source_code)


def get_introspector_data(project_name, date_str):
    introspector_summary_url = get_introspector_report_url_summary(
        project_name, date_str.replace("-", ""))

    #print(introspector_summary_url)
    introspector_report = extract_introspector_report(project_name, date_str)
    introspector_debug_info = extract_introspector_debug_info(
        project_name, date_str)

    return introspector_report, introspector_debug_info


def get_function_signature(target_function, introspector_debug_info):
    all_funcs = introspector_debug_info['all_functions_in_project']
    for func in all_funcs:
        if func['name'] == target_function:
            function_signature = ""
            function_signature += func['return_type'] + ' '
            function_signature += func['name'] + '('
            for idx in range(len(func['args'])):
                function_signature += func['args'][idx]
                if idx < len(func['args']) - 1:
                    function_signature += ', '
            function_signature += ')'
            return function_signature
    return None


def function_inspector(project_name, date_str, introspector_report,
                       introspector_debug_info, target_func):
    print("Inspecting function details for: %s" % (target_func))
    print("-" * 45)

    all_function_list = introspector_report['MergedProjectProfile'][
        'all-functions']

    func_signature = get_function_signature(target_func,
                                            introspector_debug_info)
    if func_signature is not None:
        print("-" * 45)
        print('Function signature: [%s]' % (func_signature))

    print("-" * 45)
    print("Source code of function: %s" % (target_func))
    function_source = get_source_of_func(target_func, introspector_debug_info,
                                         project_name, date_str)
    if function_source is not None:
        print(function_source)

    print("-" * 45)
    cross_reference_source = 'sam_hrecs_find_key'
    print_all_cross_references_to_function(cross_reference_source,
                                           all_function_list, project_name,
                                           date_str)


def type_inspector(project_name, date_str, introspector_debug_info, type_name):
    print("-" * 45)
    print("Printing the type struct of: %s" % (type_name))
    get_source_of_type(type_name, introspector_debug_info, project_name,
                       date_str)


def main():
    day_range = create_date_range(-1, 2)
    date_str = day_range[0]
    target_project = 'htslib'
    introspector_report, introspector_debug_info = get_introspector_data(
        target_project, date_str)

    target_func = 'sam_hrecs_find_key'
    function_inspector(target_project, date_str, introspector_report,
                       introspector_debug_info, target_func)

    target_type = 'auth_token'
    type_inspector(target_project, date_str, introspector_debug_info,
                   target_type)


if __name__ == "__main__":
    main()
