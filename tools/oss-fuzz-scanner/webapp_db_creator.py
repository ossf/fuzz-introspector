# Copyright 2023 Fuzz Introspector Authors
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
"""This module is used to create a trial DB for the webapp."""

import sys
import json
import datetime

import scanner


def get_percentage(numerator, denominator):
    percentage = round(float(numerator) / float(denominator), 2) * 100.0
    return percentage


def inspect_project(project_name):
    report_generator = scanner.get_all_reports([project_name], 300, 1)
    project, date_as_str, introspector_project = next(report_generator)
    introspector_url = scanner.get_introspector_report_url(
        project, date_as_str)
    coverage_url = scanner.get_coverage_report_url(project, date_as_str)

    all_functions = introspector_project.proj_profile.get_all_functions()

    function_list = list()
    idx = 0
    max_to_count = 1500

    project_reach_count = get_percentage(
        introspector_project.proj_profile.reached_func_count,
        introspector_project.proj_profile.total_functions)
    project_covered_funcs = get_percentage(
        len(introspector_project.proj_profile.
            get_all_runtime_covered_functions()),
        introspector_project.proj_profile.total_functions)
    project_dict = {
        'name': project_name,
        'language': 'c',
        'fuzz_count': len(introspector_project.profiles),
        'reachability': project_reach_count,
        'code-coverage': project_covered_funcs,
        'introspector-url': introspector_url,
        'code-coverage-url': coverage_url,
    }

    covered_funcs = introspector_project.proj_profile.get_all_runtime_covered_functions(
    )
    introspector_project.proj_profile.total_functions
    project_timestamp = {
        'project_name': project_name,
        'date': datetime.datetime.today().strftime('%Y-%m-%d'),
        'coverage_lines': project_covered_funcs,
        'coverage_functions': project_covered_funcs,
        'static_reachability': project_reach_count,
        'fuzzer_count': len(introspector_project.profiles),
    }

    for function_name in all_functions:
        if idx > max_to_count:
            break
        idx += 1
        function_profile = all_functions[function_name]
        reached_by_fuzzer_count = len(function_profile.reached_by_fuzzers)
        code_coverage = introspector_project.proj_profile.get_func_hit_percentage(
            function_name)

        func_cov_url = introspector_project.proj_profile.resolve_coverage_report_link(
            coverage_url.replace("/report.html",
                                 ""), function_profile.function_source_file,
            function_profile.function_linenumber,
            function_profile.function_name)

        function_list.append({
            "project_name": project_name,
            "name": function_name,
            "function_filename": function_profile.function_source_file,
            "is_reached": reached_by_fuzzer_count > 0,
            "code_coverage": code_coverage,
            "reached_by_fuzzers": reached_by_fuzzer_count,
            "function-codereport-url": func_cov_url
        })

    return project_dict, function_list, project_timestamp


def handle_projects(project_list):
    db_dict = dict()
    db_dict['function-list'] = list()
    db_dict['project-list'] = list()
    db_dict['project-timestamps'] = list()
    for project in project_list:
        print("Analysing %s" % (project))
        try:
            project_dict, function_list, project_timestamp = inspect_project(
                project)
        except:
            print("Failed %s" % (project))
            continue
        db_dict['project-list'].append(project_dict)
        db_dict['function-list'].extend(function_list)
        db_dict['project-timestamps'].append(project_timestamp)

    with open('webapp_db_result.json', 'w') as fp:
        json.dump(db_dict, fp)


def convert_db():
    with open('webapp_db_result.json', 'r') as fp:
        json_dict = json.load(fp)
    #print(json_dict)

    project_declarations = []
    proj_decl = ""
    for project in json_dict['project-list']:
        s = "Project(name='%s', language='%s', fuzz_count=%d, reach='%s', runtime_cov='%s', introspector_report_url='%s', code_coverage_report_url='%s')" % (
            project['name'], project['language'], project['fuzz_count'],
            project['reachability'], project['code-coverage'],
            project['introspector-url'], project['code-coverage-url'])
        project_declarations.append(s)
        proj_decl += "  %s,\n" % (s)

    function_declarations = []
    func_decl = ""
    for func in json_dict['function-list']:
        s = "Function(name='%s', project='%s', is_reached=%s, runtime_code_coverage=%s, function_filename='%s', code_coverage_url='%s')" % (
            func['name'], func['project_name'], func['is_reached'],
            func['code_coverage'], func['function_filename'],
            func['function-codereport-url'])
        func_decl += "  %s,\n" % (s)

    module = f"""# Auto-generated
from app.site.models import *

TEST_PROJECTS = [
{proj_decl}]

TEST_FUNCTIONS = [
{func_decl}]

def get_projects():
	return TEST_PROJECTS

def get_functions()
	return TEST_FUNCTIONS"""

    print(module)


if __name__ == "__main__":
    if sys.argv[1] == 'run':
        projects_to_analyse = [
            'htslib', 'libexif', 'hdf5', 'janet', 'opus', 'gpac', 'llhttp',
            'postfix', 'c-ares', 'brunsli', 'phpmap', 'lodepng', 'libpng',
            'nettle', 'h2o', 'libxml2', 'libgd', 'zstd', 'flac', 'icu'
        ]
        projects_to_analyse = [
            'htslib', 'libexif', 'hdf5', 'janet', 'opus', 'llhttp', 'c-ares',
            'libssh', 'libssh2'
        ]
        #projects_to_analyse = ['htslib']
        handle_projects(projects_to_analyse)
    elif sys.argv[1] == 'convert':
        convert_db()
