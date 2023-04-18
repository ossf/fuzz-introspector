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

import os
import sys
import argparse
import json
import yaml
import shutil
import datetime
import requests

DB_JSON_DB_TIMESTAMP = 'db-timestamps.json'
DB_JSON_ALL_PROJECT_TIMESTAMP = 'all-project-timestamps.json'
DB_JSON_ALL_FUNCTIONS = 'all-functions-db.json'
DB_JSON_ALL_CURRENT_FUNCS = 'all-project-current.json'

ALL_JSON_FILES = [
    DB_JSON_DB_TIMESTAMP,
    DB_JSON_ALL_PROJECT_TIMESTAMP,
    DB_JSON_ALL_FUNCTIONS,
    DB_JSON_ALL_CURRENT_FUNCS,
]


def get_introspector_summary():
    introspector_summary_url = 'https://oss-fuzz-build-logs.storage.googleapis.com/status-introspector.json'
    r = requests.get(introspector_summary_url)
    return json.loads(r.text)


def get_all_valid_projects(introspector_summary):
    successfull_projects = list()
    for project in introspector_summary['projects']:
        if project['history'][0]['success'] == True:
            successfull_projects.append(project['name'])
    return successfull_projects


def get_latest_valid_reports():
    introspector_summary = get_introspector_summary()
    successfull_projects = get_all_valid_projects(introspector_summary)
    return successfull_projects


def try_to_get_project_language(project_name):
    proj_yaml_url = 'https://raw.githubusercontent.com/google/oss-fuzz/master/projects/%s/project.yaml' % (
        project_name)
    r = requests.get(proj_yaml_url)
    project_yaml = yaml.safe_load(r.text)
    return project_yaml['language']


def get_introspector_report_url_base(project_name, datestr):
    base_url = 'https://storage.googleapis.com/oss-fuzz-introspector/{0}/inspector-report/{1}/'
    project_url = base_url.format(project_name, datestr)
    return project_url


def get_introspector_report_url_summary(project_name, datestr):
    return get_introspector_report_url_base(project_name,
                                            datestr) + "summary.json"


def get_introspector_report_url_report(project_name, datestr):
    return get_introspector_report_url_base(project_name,
                                            datestr) + "fuzz_report.html"


def get_coverage_report_url(project_name, datestr, language):
    if language == 'java' or language == 'python':
        file_report = "index.html"
    else:
        file_report = "report.html"
    base_url = 'https://storage.googleapis.com/oss-fuzz-coverage/{0}/reports/{1}/linux/{2}'
    project_url = base_url.format(project_name, datestr, file_report)
    return project_url


def get_all_functions_for_project(project_name, date_str="2023-04-11"):
    """For a given project and date gets a list of function profiles for
    the project on the givne date, and also creates a project time stamp.
    The list of function profiles and the project timestamp is returned
    as a tuple.
    """
    introspector_summary_url = get_introspector_report_url_summary(
        project_name, date_str.replace("-", ""))
    introspector_report_url = get_introspector_report_url_report(
        project_name, date_str.replace("-", ""))

    # Read the introspector atifact
    try:
        json_raw = requests.get(introspector_summary_url)
    except:
        return [], None
    try:
        json_dict = json.loads(json_raw.text)
    except:
        return [], None

    # Access all functions
    all_function_list = json_dict['MergedProjectProfile']['all-functions']
    project_stats = json_dict['MergedProjectProfile']['stats']
    amount_of_fuzzers = len(json_dict) - 2
    project_timestamp = {
        "project_name": project_name,
        "date": date_str,
        "coverage_lines": project_stats['code-coverage-function-percentage'],
        "static_reachability": project_stats['reached-complexity-percentage'],
        "fuzzer_count": amount_of_fuzzers,
        "function_count": len(all_function_list),
        "introspector_report_url": introspector_report_url,
    }

    refined_proj_list = list()
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
            len(func['Reached by Fuzzers']) > 1,
            'project':
            project_name
        })

    # The previous techniques we used to set language was quite heuristically.
    # Here, we make a more precise effort by reading the project yaml file.
    try:
        lang = try_to_get_project_language(project_name)
        if lang == 'jvm':
            lang = 'java'
        project_timestamp['language'] = lang
    except:
        # Default set to c++ as this is OSS-Fuzz's default.
        project_timestamp['language'] = 'c++'

    coverage_url = get_coverage_report_url(project_name,
                                           date_str.replace("-", ""),
                                           project_timestamp['language'])
    project_timestamp["coverage_url"] = coverage_url
    return refined_proj_list, project_timestamp


def analyse_list_of_projects(date, projects_to_analyse):
    """Creates a DB snapshot of a list of projects for a given date."""
    function_list = list()
    project_timestamps = list()
    accummulated_fuzzer_count = 0
    accummulated_function_count = 0
    for project_name in projects_to_analyse:
        print("%d" % (len(function_list)))
        project_function_list, project_timestamp = get_all_functions_for_project(
            project_name, date)
        if project_timestamp is None:
            continue
        function_list += project_function_list
        project_timestamps.append(project_timestamp)

        accummulated_fuzzer_count += project_timestamp['fuzzer_count']
        accummulated_function_count += project_timestamp['function_count']

    # Create a DB timestamp
    db_timestamp = {
        "date": date,
        "project_count": len(project_timestamps),
        "fuzzer_count": accummulated_fuzzer_count,
        "function_count": accummulated_function_count,
    }
    return function_list, project_timestamps, db_timestamp


def extend_db_timestamps(db_timestamp, output_directory):
    """Extends a DB timestamp .json file in output_directory with a given
    DB timestamp. If there is no DB timestamp .json file in the output
    directory then a DB timestamp file will be created.
    """
    existing_timestamps = []
    if os.path.isfile(os.path.join(output_directory, DB_JSON_DB_TIMESTAMP)):
        with open(os.path.join(output_directory, DB_JSON_DB_TIMESTAMP),
                  'r') as f:
            try:
                existing_timestamps = json.load(f)
            except:
                existing_timestamps = []
    else:
        existing_timestamps = []
    to_add = True
    for ts in existing_timestamps:
        if ts['date'] == db_timestamp['date']:
            to_add = False
    if to_add:
        existing_timestamps.append(db_timestamp)
        with open(os.path.join(output_directory, DB_JSON_DB_TIMESTAMP),
                  'w') as f:
            json.dump(existing_timestamps, f)


def extend_db_json_files(project_timestamps, output_directory):
    """Extends a set of DB .json files."""
    existing_timestamps = []
    if os.path.isfile(
            os.path.join(output_directory, DB_JSON_ALL_PROJECT_TIMESTAMP)):
        with open(
                os.path.join(output_directory, DB_JSON_ALL_PROJECT_TIMESTAMP),
                'r') as f:
            try:
                existing_timestamps = json.load(f)
            except:
                existing_timestamps = []
    else:
        existing_timestamps = []

    have_added = False
    for new_ts in project_timestamps:
        to_add = True
        for ts in existing_timestamps:
            if ts['date'] == new_ts['date'] and ts['project_name'] == new_ts[
                    'project_name']:
                to_add = False
        if to_add:
            existing_timestamps.append(new_ts)
            have_added = True
    if have_added:
        with open(
                os.path.join(output_directory, DB_JSON_ALL_PROJECT_TIMESTAMP),
                'w') as f:
            json.dump(existing_timestamps, f)

    with open(os.path.join(output_directory, DB_JSON_ALL_CURRENT_FUNCS),
              'w') as f:
        json.dump(project_timestamps, f)


def analyse_set_of_dates(dates, projects_to_analyse, output_directory):
    """Performs analysis of all projects in the projects_to_analyse argument for
    the given set of dates. DB .json files are stored in output_directory.
    """
    dates_to_analyse = len(dates)
    idx = 0
    for date in dates:
        print("Analysing date %s -- [%d of %d]" %
              (date, idx, dates_to_analyse))
        idx += 1
        function_list, project_timestamps, db_timestamp = analyse_list_of_projects(
            date, projects_to_analyse)
        with open(os.path.join(output_directory, DB_JSON_ALL_FUNCTIONS),
                  'w') as f:
            json.dump(function_list, f)
        extend_db_json_files(project_timestamps, output_directory)
        extend_db_timestamps(db_timestamp, output_directory)


def get_date_at_offset_as_str(day_offset=-1):
    datestr = (datetime.date.today() +
               datetime.timedelta(day_offset)).strftime("%Y-%m-%d")
    return datestr


def cleanup(output_directory):
    for f in ALL_JSON_FILES:
        if os.path.isfile(os.path.join(output_directory, f)):
            os.remove(os.path.join(output_directory, f))


def copy_input_to_output(input_dir, output_dir):
    if not os.path.isdir(input_dir):
        raise Exception("No input directory, but specified")

    if not os.path.isdir(output_dir):
        os.mkdir(output_dir)

    for f in ALL_JSON_FILES:
        if os.path.isfile(os.path.join(input_dir, f)):
            shutil.copyfile(os.path.join(input_dir, f),
                            os.path.join(output_dir, f))


def get_cmdline_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--max-projects",
        help=
        "The maximum number of projects to include in the DB. -1 will extract data about all projects.",
        default=-1,
        type=int)
    parser.add_argument("--days-to-analyse",
                        help="The number of days to analyse",
                        default=1,
                        type=int)
    parser.add_argument("--output-dir",
                        help="Output directory for the produced .json files",
                        default=os.getcwd())
    parser.add_argument("--input-dir",
                        help="Input directory with existing .json files",
                        default=None)
    parser.add_argument("--base-offset",
                        help="Day offset",
                        type=int,
                        default=1)
    parser.add_argument("--cleanup", action="store_true")

    return parser


def create_db(max_projects, days_to_analyse, output_directory, input_directory,
              day_offset, to_cleanup):
    if input_directory is not None:
        copy_input_to_output(input_directory, output_directory)

    if not os.path.isdir(output_directory):
        os.mkdir(output_directory)

    project_list = get_latest_valid_reports()
    if max_projects > 0 and len(project_list) > max_projects:
        project_list = project_list[0:max_projects]

    if to_cleanup:
        cleanup(output_directory)
    dates_list = []
    range_to_analyse = range(day_offset, day_offset + days_to_analyse)
    for i in list(reversed(list(range_to_analyse))):
        dates_list.append(get_date_at_offset_as_str(i * -1))

    analyse_set_of_dates(dates_list, project_list, output_directory)


if __name__ == "__main__":
    parser = get_cmdline_parser()
    args = parser.parse_args()
    create_db(args.max_projects, args.days_to_analyse, args.output_dir,
              args.input_dir, args.base_offset, args.cleanup)
