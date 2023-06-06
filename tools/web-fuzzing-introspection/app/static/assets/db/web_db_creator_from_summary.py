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
"""Helper for creating the necessary .json files used by the webapp."""
import os
import sys
import argparse
import json
import yaml
import shutil
import logging
import datetime
import requests
import subprocess
from threading import Thread

DB_JSON_DB_TIMESTAMP = 'db-timestamps.json'
DB_JSON_ALL_PROJECT_TIMESTAMP = 'all-project-timestamps.json'
DB_JSON_ALL_FUNCTIONS = 'all-functions-db.json'
DB_JSON_ALL_CURRENT_FUNCS = 'all-project-current.json'
DB_JSON_ALL_BRANCH_BLOCKERS = 'all-branch-blockers.json'
DB_BUILD_STATUS_JSON = 'build-status.json'

ALL_JSON_FILES = [
    DB_JSON_DB_TIMESTAMP,
    DB_JSON_ALL_PROJECT_TIMESTAMP,
    DB_JSON_ALL_FUNCTIONS,
    DB_JSON_ALL_CURRENT_FUNCS,
]

OSS_FUZZ_BUILD_STATUS_URL = 'https://oss-fuzz-build-logs.storage.googleapis.com'
INTROSPECTOR_BUILD_JSON = 'status-introspector.json'
COVERAGE_BUILD_JSON = 'status-coverage.json'
FUZZ_BUILD_JSON = 'status.json'
OSS_FUZZ_BUILD_LOG_BASE = 'https://oss-fuzz-build-logs.storage.googleapis.com/log-'

OSS_FUZZ_CLONE = ""

logging.getLogger("requests").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)

logger = logging.getLogger(name=__name__)


def git_clone_project(github_url, destination):
    cmd = ["git clone", github_url, destination]
    try:
        subprocess.check_call(" ".join(cmd),
                              shell=True,
                              timeout=600,
                              stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        return False
    except subprocess.CalledProcessError:
        return False
    return True

def get_projects_build_status():
    fuzz_build_url = OSS_FUZZ_BUILD_STATUS_URL + '/' + FUZZ_BUILD_JSON
    coverage_build_url = OSS_FUZZ_BUILD_STATUS_URL + '/' + COVERAGE_BUILD_JSON
    introspector_build_url = OSS_FUZZ_BUILD_STATUS_URL + '/' + INTROSPECTOR_BUILD_JSON

    fuzz_build_raw = requests.get(fuzz_build_url, timeout=20).text
    coverage_build_raw = requests.get(coverage_build_url, timeout=20).text
    introspector_build_raw = requests.get(introspector_build_url, timeout=20).text

    fuzz_build_json = json.loads(fuzz_build_raw)
    cov_build_json = json.loads(coverage_build_raw)
    introspector_build_json = json.loads(introspector_build_raw)

    build_status_dict = dict()
    for p in fuzz_build_json['projects']:
        project_dict = build_status_dict.get(p['name'], dict())
        project_dict['fuzz-build'] = p['history'][0]['success']
        project_dict['fuzz-build-log'] = OSS_FUZZ_BUILD_LOG_BASE + p['history'][0]['build_id'] + '.txt'
        build_status_dict[p['name']] = project_dict
    for p in cov_build_json['projects']:
        project_dict = build_status_dict.get(p['name'], dict())
        project_dict['cov-build'] = p['history'][0]['success']
        project_dict['cov-build-log'] = OSS_FUZZ_BUILD_LOG_BASE + p['history'][0]['build_id'] + '.txt'
        build_status_dict[p['name']] = project_dict
    for p in introspector_build_json['projects']:
        project_dict = build_status_dict.get(p['name'], dict())
        project_dict['introspector-build'] = p['history'][0]['success']
        project_dict['introspector-build-log'] = OSS_FUZZ_BUILD_LOG_BASE + p['history'][0]['build_id'] + '.txt'
        build_status_dict[p['name']] = project_dict

    # Ensure all fields are set in each dictionary
    needed_keys = ['introspector-build', 'fuzz-build', 'cov-build', 'introspector-build-log', 'cov-build-log', 'fuzz-build-log']
    for project_name in build_status_dict:
        project_dict = build_status_dict[project_name]
        for needed_key in needed_keys:
            if needed_key not in project_dict:
                project_dict[needed_key] = 'N/A'

    print("Going through all of the projects")
    for project_name in build_status_dict:
        try:
            project_language = try_to_get_project_language(project_name)
        except:
            project_language = 'N/A'
        build_status_dict[project_name]['language'] = project_language
    print("Number of projects: %d"%(len(build_status_dict)))
    return build_status_dict

def get_introspector_summary():
    introspector_summary_url = OSS_FUZZ_BUILD_STATUS_URL + '/' + INTROSPECTOR_BUILD_JSON
    r = requests.get(introspector_summary_url, timeout=20)
    return json.loads(r.text)


def get_all_valid_projects(introspector_summary):
    successfull_projects = list()
    for project in introspector_summary['projects']:
        if project['history'][0]['success'] == True:
            successfull_projects.append(project['name'])
    return successfull_projects


def get_latest_valid_reports():
    try:
        introspector_summary = get_introspector_summary()
    except:
        return []
    successfull_projects = get_all_valid_projects(introspector_summary)
    return successfull_projects


def try_to_get_project_language(project_name):
    if os.path.isdir(OSS_FUZZ_CLONE):
        local_project_path = os.path.join(OSS_FUZZ_CLONE, "projects", project_name)
        if os.path.isdir(local_project_path):
            project_yaml_path = os.path.join(local_project_path, "project.yaml")
            if os.path.isfile(project_yaml_path):
                with open(project_yaml_path, "r") as f:
                    project_yaml = yaml.safe_load(f.read())
                    return project_yaml['language']
    else:
        proj_yaml_url = 'https://raw.githubusercontent.com/google/oss-fuzz/master/projects/%s/project.yaml' % (
            project_name)
        r = requests.get(proj_yaml_url, timeout=10)
        project_yaml = yaml.safe_load(r.text)
        return project_yaml['language']
    return "N/A"


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


def get_all_functions_for_project(project_name, date_str,
                                  should_include_details, manager_return_dict):
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
        json_raw = requests.get(introspector_summary_url, timeout=10)
    except:
        return
    try:
        json_dict = json.loads(json_raw.text)
    except:
        return

    # Access all functions
    all_function_list = json_dict['MergedProjectProfile']['all-functions']
    project_stats = json_dict['MergedProjectProfile']['stats']
    amount_of_fuzzers = len(json_dict) - 2
    number_of_functions = len(all_function_list)

    functions_covered_estimate = int(number_of_functions * float(0.01 * project_stats['code-coverage-function-percentage']))
    project_timestamp = {
        "project_name": project_name,
        "date": date_str,
        "coverage_lines": project_stats['code-coverage-function-percentage'],
        "static_reachability": project_stats['reached-complexity-percentage'],
        "fuzzer_count": amount_of_fuzzers,
        "function_count": len(all_function_list),
        "introspector_report_url": introspector_report_url,
        "functions_covered_estimate": functions_covered_estimate,
    }

    refined_proj_list = list()
    if should_include_details:
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
                project_name,
                'accumulated_cyclomatic_complexity':
                func['Accumulated cyclomatic complexity'],
                'llvm-instruction-count':
                func['I Count'],
                'undiscovered-complexity':
                func['Undiscovered complexity'],
            })

    # Get all branch blockers
    branch_pairs = list()
    if should_include_details:
        for key in json_dict:
            # We look for dicts with fuzzer-specific content. The following two
            # are not such keys, so skip them.
            if key == "analyses" or key == "MergedProjectProfile":
                continue

            # Fuzzer-specific dictionary, get the contents of it.
            val = json_dict[key]
            if not isinstance(val, dict):
                continue

            branch_blockers = val.get('branch_blockers', None)
            if branch_blockers == None or not isinstance(
                    branch_blockers, list):
                continue

            for branch_blocker in branch_blockers:
                function_blocked = branch_blocker.get('function_name', None)
                blocked_unique_not_covered_complexity = branch_blocker.get(
                    'blocked_unique_not_covered_complexity', None)
                if function_blocked == None:
                    continue
                if blocked_unique_not_covered_complexity == None:
                    continue

                branch_pairs.append({
                    'project':
                    project_name,
                    'function-name':
                    function_blocked,
                    'blocked-runtime-coverage':
                    blocked_unique_not_covered_complexity
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
    dictionary_key = '%s###%s' % (project_name, date_str)
    manager_return_dict[dictionary_key] = {
        'refined_proj_list': refined_proj_list,
        'branch_pairs': branch_pairs,
        'project_timestamp': project_timestamp
    }
    return


def analyse_list_of_projects(date, projects_to_analyse,
                             should_include_details):
    """Creates a DB snapshot of a list of projects for a given date."""
    function_list = list()
    fuzz_branch_blocker_list = list()
    project_timestamps = list()
    accummulated_fuzzer_count = 0
    accummulated_function_count = 0
    accummulated_covered_functions = 0
    idx = 0
    jobs = []
    return_dict = dict()

    batch_size = 20 if not should_include_details else 5
    all_batches = [
        projects_to_analyse[x:x + batch_size]
        for x in range(0, len(projects_to_analyse), batch_size)
    ]

    for batch in all_batches:
        for project_name in batch:
            idx += 1
            logger.debug("%d" % (len(function_list)))
            t = Thread(target=get_all_functions_for_project,
                       args=(project_name, date, should_include_details,
                             return_dict))
            jobs.append(t)
            t.start()

        for proc in jobs:
            proc.join()

    # Accummulate data

    for key in return_dict:
        project_function_list = return_dict[key]['refined_proj_list']
        branch_pairs = return_dict[key]['branch_pairs']
        project_timestamp = return_dict[key]['project_timestamp']

        function_list += project_function_list
        fuzz_branch_blocker_list += branch_pairs
        project_timestamps.append(project_timestamp)

        accummulated_fuzzer_count += project_timestamp['fuzzer_count']
        accummulated_function_count += project_timestamp['function_count']

        accummulated_covered_functions += project_timestamp['functions_covered_estimate']

    # Create a DB timestamp
    db_timestamp = {
        "date": date,
        "project_count": len(project_timestamps),
        "fuzzer_count": accummulated_fuzzer_count,
        "function_count": accummulated_function_count,
        "function_coverage_estimate": accummulated_covered_functions,
    }
    return function_list, fuzz_branch_blocker_list, project_timestamps, db_timestamp


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


def update_db_files(db_timestamp, project_timestamps, function_list,
                    fuzz_branch_blocker_list, output_directory,
                    should_include_details):
    logger.info(
        "Updating the database with DB snapshot. Number of functions in total: %d"
        % (db_timestamp['function_count']))
    if should_include_details:
        with open(os.path.join(output_directory, DB_JSON_ALL_FUNCTIONS),
                  'w') as f:
            json.dump(function_list, f)
        with open(os.path.join(output_directory, DB_JSON_ALL_BRANCH_BLOCKERS),
                  'w') as f:
            json.dump(fuzz_branch_blocker_list, f)
    extend_db_json_files(project_timestamps, output_directory)
    extend_db_timestamps(db_timestamp, output_directory)

def update_build_status(build_dict):
    with open(DB_BUILD_STATUS_JSON, "w") as f:
        json.dump(build_dict, f)

def analyse_set_of_dates(dates, projects_to_analyse, output_directory):
    """Pe/rforms analysis of all projects in the projects_to_analyse argument for
    the given set of dates. DB .json files are stored in output_directory.
    """
    dates_to_analyse = len(dates)
    idx = 1
    for date in dates:
        current_time = datetime.datetime.now().strftime("%H:%M:%S")
        logger.info("Analysing date %s -- [%d of %d] -- %s" %
                    (date, idx, dates_to_analyse, current_time))
        idx += 1
        should_include_details = idx == len(dates)
        function_list, fuzz_branch_blocker_list, project_timestamps, db_timestamp = analyse_list_of_projects(
            date, projects_to_analyse, should_include_details)
        update_db_files(db_timestamp, project_timestamps, function_list,
                        fuzz_branch_blocker_list, output_directory,
                        should_include_details)


def get_date_at_offset_as_str(day_offset=-1):
    datestr = (datetime.date.today() +
               datetime.timedelta(day_offset)).strftime("%Y-%m-%d")
    return datestr


def cleanup(output_directory):
    for f in ALL_JSON_FILES:
        if os.path.isfile(os.path.join(output_directory, f)):
            os.remove(os.path.join(output_directory, f))


def copy_input_to_output(input_dir, output_dir):
    if input_dir == output_dir:
        return

    if not os.path.isdir(input_dir):
        raise Exception("No input directory, but specified")

    if not os.path.isdir(output_dir):
        os.mkdir(output_dir)

    for f in ALL_JSON_FILES:
        if os.path.isfile(os.path.join(input_dir, f)):
            shutil.copyfile(os.path.join(input_dir, f),
                            os.path.join(output_dir, f))


def setup_folders(input_directory, output_directory):
    if input_directory is not None:
        copy_input_to_output(input_directory, output_directory)
    if not os.path.isdir(output_directory):
        os.mkdir(output_directory)


def create_date_range(day_offset, days_to_analyse):
    date_range = []
    range_to_analyse = range(day_offset + days_to_analyse, day_offset, -1)
    for i in range_to_analyse:
        date_range.append(get_date_at_offset_as_str(i * -1))
    return date_range


def create_db(max_projects, days_to_analyse, output_directory, input_directory,
              day_offset, to_cleanup, since_date):
    global OSS_FUZZ_CLONE
    setup_folders(input_directory, output_directory)
    project_list = get_latest_valid_reports()
    if max_projects > 0 and len(project_list) > max_projects:
        project_list = project_list[0:max_projects]

    if to_cleanup:
        cleanup(output_directory)

    if since_date != None:
        start_date = datetime.datetime.strptime(since_date, "%d-%m-%Y").date()
        today = datetime.date.today()
        delta = today - start_date
        days_to_analyse = delta.days - 1
        day_offset = 1

    date_range = create_date_range(day_offset, days_to_analyse)

    logger.info("Creating a DB with the specifications:")
    logger.info("- Date range: [%s : %s]" %
                (str(date_range[0]), str(date_range[-1])))
    logger.info("- Total of %d projects to analyse" % (len(project_list)))
    if input_directory is not None:
        logger.info("- Extending upon the DB in %s" % (str(input_directory)))
    else:
        logger.info("-Creating the DB from scratch")

    oss_fuzz_local_clone = os.path.join(output_directory, "oss-fuzz-clone")
    if os.path.isdir(oss_fuzz_local_clone):
        shutil.rmtree(oss_fuzz_local_clone)
    git_clone_project("https://github.com/google/oss-fuzz", oss_fuzz_local_clone)

    OSS_FUZZ_CLONE = oss_fuzz_local_clone
    build_status_dict = get_projects_build_status()
    update_build_status(build_status_dict)
    analyse_set_of_dates(date_range, project_list, output_directory)


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
    parser.add_argument(
        "--since-date",
        help="Include data from this date an onwards, in format \"d-m-y\"",
        default=None)
    parser.add_argument("--cleanup", action="store_true")
    parser.add_argument("--debug", action="store_true")
    return parser


def main():
    parser = get_cmdline_parser()
    args = parser.parse_args()
    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)
    create_db(args.max_projects, args.days_to_analyse, args.output_dir,
              args.input_dir, args.base_offset, args.cleanup, args.since_date)


if __name__ == "__main__":
    main()
