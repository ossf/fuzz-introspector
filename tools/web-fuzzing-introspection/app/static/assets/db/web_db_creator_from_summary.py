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
import io
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
import zipfile
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

INTROSPECTOR_WEBAPP_ZIP = 'https://introspector.oss-fuzz.com/static/assets/db/db-archive.zip'

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
    introspector_build_raw = requests.get(introspector_build_url,
                                          timeout=20).text

    fuzz_build_json = json.loads(fuzz_build_raw)
    cov_build_json = json.loads(coverage_build_raw)
    introspector_build_json = json.loads(introspector_build_raw)

    build_status_dict = dict()
    for p in fuzz_build_json['projects']:
        project_dict = build_status_dict.get(p['name'], dict())
        project_dict['fuzz-build'] = p['history'][0]['success']
        project_dict['fuzz-build-log'] = OSS_FUZZ_BUILD_LOG_BASE + p[
            'history'][0]['build_id'] + '.txt'
        build_status_dict[p['name']] = project_dict
    for p in cov_build_json['projects']:
        project_dict = build_status_dict.get(p['name'], dict())
        project_dict['cov-build'] = p['history'][0]['success']
        project_dict['cov-build-log'] = OSS_FUZZ_BUILD_LOG_BASE + p['history'][
            0]['build_id'] + '.txt'
        build_status_dict[p['name']] = project_dict
    for p in introspector_build_json['projects']:
        project_dict = build_status_dict.get(p['name'], dict())
        project_dict['introspector-build'] = p['history'][0]['success']
        project_dict['introspector-build-log'] = OSS_FUZZ_BUILD_LOG_BASE + p[
            'history'][0]['build_id'] + '.txt'
        build_status_dict[p['name']] = project_dict

    # Ensure all fields are set in each dictionary
    needed_keys = [
        'introspector-build', 'fuzz-build', 'cov-build',
        'introspector-build-log', 'cov-build-log', 'fuzz-build-log'
    ]
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
    print("Number of projects: %d" % (len(build_status_dict)))
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
        local_project_path = os.path.join(OSS_FUZZ_CLONE, "projects",
                                          project_name)
        if os.path.isdir(local_project_path):
            project_yaml_path = os.path.join(local_project_path,
                                             "project.yaml")
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


def get_fuzzer_stats_fuzz_count_url(project_name, date_str):
    base_url = 'https://storage.googleapis.com/oss-fuzz-coverage/{0}/fuzzer_stats/{1}/coverage_targets.txt'
    coverage_targets = base_url.format(project_name, date_str)
    return coverage_targets


def get_fuzzer_stats_fuzz_count(project_name, date_str):
    coverage_stats_url = get_fuzzer_stats_fuzz_count_url(
        project_name, date_str)
    coverage_summary_raw = requests.get(coverage_stats_url, timeout=20).text
    if "The specified key does not exist" in coverage_summary_raw:
        return None
    return coverage_summary_raw


def get_code_coverage_summary_url(project_name, datestr):
    base_url = 'https://storage.googleapis.com/oss-fuzz-coverage/{0}/reports/{1}/linux/summary.json'
    project_url = base_url.format(project_name, datestr)
    return project_url


def get_coverage_report_url(project_name, datestr, language):
    if language == 'java' or language == 'python' or language == 'go':
        file_report = "index.html"
    else:
        file_report = "report.html"
    base_url = 'https://storage.googleapis.com/oss-fuzz-coverage/{0}/reports/{1}/linux/{2}'
    project_url = base_url.format(project_name, datestr, file_report)
    return project_url


def get_code_coverage_summary(project_name, datestr):
    cov_summary_url = get_code_coverage_summary_url(project_name, datestr)
    coverage_summary_raw = requests.get(cov_summary_url, timeout=20).text
    try:
        json_dict = json.loads(coverage_summary_raw)
        return json_dict
    except:
        return None


def extract_introspector_report(project_name, date_str):
    introspector_summary_url = get_introspector_report_url_summary(
        project_name, date_str.replace("-", ""))
    introspector_report_url = get_introspector_report_url_report(
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


def rename_annotated_cfg(original_annotated_cfg):
    """Renames an annotated CFG as it is from introspector."""
    new_annotated_cfg = list()
    for fuzzer_name in original_annotated_cfg:
        elem = {
            'fuzzer_name': fuzzer_name,
            'src_file': original_annotated_cfg[fuzzer_name]['src_file'],
            'destinations': []
        }
        for dest_elem in original_annotated_cfg[fuzzer_name]['destinations']:
            refined_dest_elem = dict()
            for k, v in dest_elem.items():
                refined_dest_elem[k.replace("-", "_")] = v
            elem['destinations'].append(refined_dest_elem)

        new_annotated_cfg.append(elem)
    return new_annotated_cfg


def extract_project_data(project_name, date_str, should_include_details,
                         manager_return_dict):
    """
    Extracts data about a given project on a given date. The data will be placed
    in manager_return dict.

    The data that will be exracted include:
    - Details extracted from introspector reports
        - Function profiles
        - Static reachability
        - Number of fuzzers
    - Details extracted from code coverage reports
        - Lines of code totally in the project
        - Lines of code covered at runtime
    """
    amount_of_fuzzers = None

    # TODO (David): handle the case where there is neither code coverage or introspector reports.
    # In this case we should simply return an error so it will not be included. This is also useful
    # for creating history

    # Extract programming language of the project
    # The previous techniques we used to set language was quite heuristically.
    # Here, we make a more precise effort by reading the project yaml file.
    try:
        project_language = try_to_get_project_language(project_name)
        if project_language == 'jvm':
            project_language = 'java'
    except:
        # Default set to c++ as this is OSS-Fuzz's default.
        project_language = 'c++'

    # Extract code coverage and introspector reports.
    code_coverage_summary = get_code_coverage_summary(
        project_name, date_str.replace("-", ""))
    cov_fuzz_stats = get_fuzzer_stats_fuzz_count(project_name,
                                                 date_str.replace("-", ""))
    introspector_report = extract_introspector_report(project_name, date_str)
    introspector_report_url = get_introspector_report_url_report(
        project_name, date_str.replace("-", ""))

    # Currently, we fail if any of code_coverage_summary of introspector_report is
    # None. This should later be adjusted such that we can continue if we only
    # have code coverage but no introspector data. However, we need to adjust
    # the OSS-Fuzz data generated before doing so, we need some basic stats e.g.
    # number of fuzzers, which are currently only available in Fuzz Introspector.
    #if code_coverage_summary == None and introspector_report == None:
    #    # Do not adjust the `manager_return_dict`, so nothing will be included in
    #    # the report.
    #   return

    # We need either:
    # - coverage + fuzzer stats
    # - introspector
    # - both
    if not ((code_coverage_summary != None and cov_fuzz_stats != None)
            or introspector_report != None):
        return

    if introspector_report == None:
        introspector_data_dict = None
    else:
        # Access all functions
        all_function_list = introspector_report['MergedProjectProfile'][
            'all-functions']
        project_stats = introspector_report['MergedProjectProfile']['stats']
        amount_of_fuzzers = len(introspector_report) - 2
        number_of_functions = len(all_function_list)

        functions_covered_estimate = project_stats[
            'code-coverage-function-percentage']
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
                    func.get('raw-function-name', 'N/A')
                })

        # Get all branch blockers
        branch_pairs = list()
        annotated_cfg = dict()
        if should_include_details:
            for key in introspector_report:
                # We look for dicts with fuzzer-specific content. The following two
                # are not such keys, so skip them.
                if key == 'analyses':
                    if 'AnnotatedCFG' in introspector_report[key]:
                        annotated_cfg = rename_annotated_cfg(
                            introspector_report['analyses']['AnnotatedCFG'])

                if key == "MergedProjectProfile" or key == 'analyses':
                    continue

                # Fuzzer-specific dictionary, get the contents of it.
                val = introspector_report[key]
                if not isinstance(val, dict):
                    continue

                branch_blockers = val.get('branch_blockers', None)
                if branch_blockers == None or not isinstance(
                        branch_blockers, list):
                    continue

                for branch_blocker in branch_blockers:
                    function_blocked = branch_blocker.get(
                        'function_name', None)
                    blocked_unique_not_covered_complexity = branch_blocker.get(
                        'blocked_unique_not_covered_complexity', None)
                    if blocked_unique_not_covered_complexity < 5:
                        continue
                    if function_blocked == None:
                        continue
                    if blocked_unique_not_covered_complexity == None:
                        continue

                    branch_pairs.append({
                        'project':
                        project_name,
                        'function_name':
                        function_blocked,
                        'blocked_runtime_coverage':
                        blocked_unique_not_covered_complexity,
                        'source_file':
                        branch_blocker.get('source_file', "N/A"),
                        'linenumber':
                        branch_blocker.get('branch_line_number', -1),
                        'blocked_unique_functions':
                        branch_blocker.get('blocked_unique_functions', [])
                    })

        introspector_data_dict = {
            "introspector_report_url": introspector_report_url,
            "coverage_lines":
            project_stats['code-coverage-function-percentage'],
            "static_reachability":
            project_stats['reached-complexity-percentage'],
            "fuzzer_count": amount_of_fuzzers,
            "function_count": len(all_function_list),
            "functions_covered_estimate": functions_covered_estimate,
            'refined_proj_list': refined_proj_list,
            'branch_pairs': branch_pairs,
            'annotated_cfg': annotated_cfg,
        }

    # Extract data from the code coverage reports
    if code_coverage_summary == None:
        code_coverage_data_dict = None
    else:
        if code_coverage_summary != None:
            try:
                line_total_summary = code_coverage_summary['data'][0][
                    'totals']['lines']
            except KeyError:
                # This can happen in Python, where the correct code formatting was only done
                # May 3rd 2023: https://github.com/google/oss-fuzz/pull/10201
                return
            #line_total_summary['percent']
            # For the sake of consistency, we re-calculate the percentage. This is because
            # some of the implentations have a value 0 <= p <= 1 and some have 0 <= p <= 100.
            try:
                line_total_summary['percent'] = round(
                    100.0 * (float(line_total_summary['covered']) /
                             float(line_total_summary['count'])), 2)
            except:
                pass
        else:
            line_total_summary = {
                'count': 0,
                'covered': 0,
                'percent': 0,
            }

        coverage_url = get_coverage_report_url(project_name,
                                               date_str.replace("-", ""),
                                               project_language)
        code_coverage_data_dict = {
            'coverage_url': coverage_url,
            'line_coverage': line_total_summary
        }

    if cov_fuzz_stats != None:
        all_fuzzers = cov_fuzz_stats.split("\n")
        if all_fuzzers[-1] == '':
            all_fuzzers = all_fuzzers[0:-1]
        amount_of_fuzzers = len(all_fuzzers)

    project_timestamp = {
        "project_name": project_name,
        "date": date_str,
        'language': project_language,
        'coverage-data': code_coverage_data_dict,
        'introspector-data': introspector_data_dict,
        'fuzzer-count': amount_of_fuzzers,
    }

    dictionary_key = '%s###%s' % (project_name, date_str)
    manager_return_dict[dictionary_key] = {
        #'refined_proj_list': refined_proj_list,
        #'branch_pairs': branch_pairs,
        'project_timestamp': project_timestamp,
        "introspector-data-dict": introspector_data_dict,
        "coverage-data-dict": code_coverage_data_dict,
    }
    return


def analyse_list_of_projects(date, projects_to_analyse,
                             should_include_details):
    """Creates a DB snapshot of a list of projects for a given date.

    Returns:
    - A db timestamp, which holds overall stats about the database on a given date.
    - A list of all functions for this date if `should_include_details` is True.
    - A list of all branch blockers on this given date if `should_include_details` is True.
    - A list of project timestamps with information about each project.
      - This holds data relative to whether coverage and introspector builds succeeds.

    """
    function_list = list()
    fuzz_branch_blocker_list = list()
    project_timestamps = list()
    accummulated_fuzzer_count = 0
    accummulated_function_count = 0
    accummulated_covered_functions = 0
    accummulated_lines_total = 0
    accummulated_lines_covered = 0

    # Create a DB timestamp
    db_timestamp = {
        "date": date,
        "project_count": -1,
        "fuzzer_count": 0,
        "function_count": 0,
        "function_coverage_estimate": 0,
        "accummulated_lines_total": 0,
        "accummulated_lines_covered": 0,
    }

    idx = 0
    jobs = []
    analyses_dictionary = dict()

    project_name_list = list(projects_to_analyse.keys())

    batch_size = 20 if not should_include_details else 5
    all_batches = [
        project_name_list[x:x + batch_size]
        for x in range(0, len(project_name_list), batch_size)
    ]

    # Extract data from all of the projects using multi-threaded approach.
    for batch in all_batches:
        for project_name in batch:
            idx += 1
            logger.debug("%d" % (len(function_list)))
            t = Thread(target=extract_project_data,
                       args=(project_name, date, should_include_details,
                             analyses_dictionary))
            jobs.append(t)
            t.start()

        for proc in jobs:
            proc.join()

    # Accummulate the data from all the projects.
    for project_key in analyses_dictionary:
        # Append project timestamp to the list of timestamps
        project_timestamp = analyses_dictionary[project_key][
            'project_timestamp']
        project_timestamps.append(project_timestamp)
        db_timestamp['fuzzer_count'] += project_timestamp['fuzzer-count']

        # Accummulate all function list and branch blockers
        introspector_dictionary = project_timestamp.get(
            'introspector-data', None)
        if introspector_dictionary != None:
            function_list += introspector_dictionary['refined_proj_list']
            # Remove the function list because we don't want it anymore.
            introspector_dictionary.pop('refined_proj_list')
            fuzz_branch_blocker_list += introspector_dictionary['branch_pairs']

            # Accummulate various stats for the DB timestamp.
            db_timestamp['function_count'] += introspector_dictionary[
                'function_count']
            db_timestamp[
                'function_coverage_estimate'] += introspector_dictionary[
                    'functions_covered_estimate']

        coverage_dictionary = analyses_dictionary[project_key].get(
            'coverage-data-dict', None)
        if coverage_dictionary != None:
            # Accummulate various stats for the DB timestamp.
            db_timestamp["accummulated_lines_total"] += coverage_dictionary[
                'line_coverage']['count']
            db_timestamp["accummulated_lines_covered"] += coverage_dictionary[
                'line_coverage']['covered']

            # We include in project count if coverage is in here
            db_timestamp["project_count"] += 1

    # Return:
    # - all functions
    # - all branch blockers
    # - a list of project timestamps
    # - the DB timestamp
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

    # Write a zip folder the values that make sense to save
    if should_include_details:
        with zipfile.ZipFile('db-archive.zip', 'w') as zip_object:
            zip_object.write(os.path.join(output_directory,
                                          DB_JSON_DB_TIMESTAMP),
                             DB_JSON_DB_TIMESTAMP,
                             compress_type=zipfile.ZIP_DEFLATED)
            zip_object.write(os.path.join(output_directory,
                                          DB_JSON_ALL_PROJECT_TIMESTAMP),
                             DB_JSON_ALL_PROJECT_TIMESTAMP,
                             compress_type=zipfile.ZIP_DEFLATED)


def update_build_status(build_dict):
    with open(DB_BUILD_STATUS_JSON, "w") as f:
        json.dump(build_dict, f)


def is_date_in_db(date, output_directory):
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

    in_db = False
    for ts in existing_timestamps:
        if ts['date'] == date:
            in_db = True
    return in_db


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

        # Is this the last date to analyse?
        is_end = idx == len(dates)
        print("Is end: %s" % (is_end))

        # Increment counter. Must happen after our is_end check.
        idx += 1

        # If it's not the last date and we have cached data, use the cache.
        if is_end == False and is_date_in_db(date, output_directory):
            logger.info("Date already analysed, skipping")
            continue

        function_list, fuzz_branch_blocker_list, project_timestamps, db_timestamp = analyse_list_of_projects(
            date, projects_to_analyse, should_include_details=is_end)
        update_db_files(db_timestamp,
                        project_timestamps,
                        function_list,
                        fuzz_branch_blocker_list,
                        output_directory,
                        should_include_details=is_end)


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


def extract_oss_fuzz_build_status(output_directory):
    """Extracts fuzz/coverage/introspector build status from OSS-Fuzz stats."""
    global OSS_FUZZ_CLONE

    # Extract the build status of all OSS-Fuzz projects
    # Create a local clone of OSS-Fuzz. This is used for checking language of a project easily.
    oss_fuzz_local_clone = os.path.join(output_directory, "oss-fuzz-clone")
    if os.path.isdir(oss_fuzz_local_clone):
        shutil.rmtree(oss_fuzz_local_clone)
    git_clone_project("https://github.com/google/oss-fuzz",
                      oss_fuzz_local_clone)

    OSS_FUZZ_CLONE = oss_fuzz_local_clone
    build_status_dict = get_projects_build_status()
    update_build_status(build_status_dict)
    return build_status_dict


def create_date_range(day_offset, days_to_analyse):
    date_range = []
    range_to_analyse = range(day_offset + days_to_analyse, day_offset, -1)
    for i in range_to_analyse:
        date_range.append(get_date_at_offset_as_str(i * -1))
    return date_range


def setup_github_cache():
    if os.path.isdir("github_cache"):
        shutil.rmtree("github_cache")

    git_clone_project(
        "https://github.com/DavidKorczynski/oss-fuzz-db-fuzzintro",
        "github_cache")
    if not os.path.isdir("github_cache"):
        return False
    db_zipfile = os.path.join("github_cache", "db-stamp.zip")
    if os.path.isfile(db_zipfile):
        with zipfile.ZipFile(db_zipfile, 'r') as zip_ref:
            zip_ref.extractall("github_cache")


def setup_webapp_cache():
    print("Getting the db archive")
    r = requests.get(INTROSPECTOR_WEBAPP_ZIP, stream=True)
    db_archive = zipfile.ZipFile(io.BytesIO(r.content))

    if os.path.isdir("extracted-db-archive"):
        shutil.rmtree("extracted-db-archive")
    os.mkdir("extracted-db-archive")

    db_archive.extractall("extracted-db-archive")
    print("Extracted it all")

    # Copy over the files
    shutil.copyfile(os.path.join("extracted-db-archive", DB_JSON_DB_TIMESTAMP),
                    DB_JSON_DB_TIMESTAMP)
    shutil.copyfile(
        os.path.join("extracted-db-archive", DB_JSON_ALL_PROJECT_TIMESTAMP),
        DB_JSON_ALL_PROJECT_TIMESTAMP)

    # If we get to here it all went well.


def create_db(max_projects, days_to_analyse, output_directory, input_directory,
              day_offset, to_cleanup, since_date, use_github_cache,
              use_webapp_cache):
    got_cache = False
    if use_webapp_cache:
        try:
            setup_webapp_cache()
            # If we got to here, that means the cache download went well.
            got_cache = True
        except:
            got_cache = False

    if use_github_cache and not got_cache:
        setup_github_cache()
        input_directory = "github_cache"

    setup_folders(input_directory, output_directory)

    # Extract fuzz/coverage/introspector build status of each project and extract
    projects_list_build_status = extract_oss_fuzz_build_status(
        output_directory)
    projects_to_analyse = dict()
    for p in projects_list_build_status:
        #if projects_list_build_status[p][
        #        'introspector-build'] == True or projects_list_build_status[
        #            p]['cov-build'] == True:
        #if projects_list_build_status[p]['cov-build'] == True:
        projects_to_analyse[p] = projects_list_build_status[p]
    #for project_name in projects_list_build_status:
    #    print("project: %s"%(project_name))

    # Reduce the amount of projects if needed.
    if max_projects > 0 and len(projects_to_analyse) > max_projects:
        tmp_dictionary = dict()
        idx = 0
        for k in projects_to_analyse:
            if idx > max_projects:
                break
            tmp_dictionary[k] = projects_to_analyse[k]
            idx += 1
        projects_to_analyse = tmp_dictionary

    if to_cleanup:
        cleanup(output_directory)

    if since_date != None:
        start_date = datetime.datetime.strptime(since_date, "%d-%m-%Y").date()
        today = datetime.date.today()
        delta = today - start_date
        days_to_analyse = delta.days - 1
        day_offset = 0

    date_range = create_date_range(day_offset, days_to_analyse)
    print(date_range)
    logger.info("Creating a DB with the specifications:")
    logger.info("- Date range: [%s : %s]" %
                (str(date_range[0]), str(date_range[-1])))
    logger.info("- Total of %d projects to analyse" %
                (len(projects_to_analyse)))
    if input_directory is not None:
        logger.info("- Extending upon the DB in %s" % (str(input_directory)))
    else:
        logger.info("-Creating the DB from scratch")

    print("Starting analysis of max %d projects" % (len(projects_to_analyse)))

    analyse_set_of_dates(date_range, projects_to_analyse, output_directory)


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
    parser.add_argument("--use_gh_cache", action="store_false")
    parser.add_argument("--use_webapp_cache", action="store_false")
    return parser


def main():
    parser = get_cmdline_parser()
    args = parser.parse_args()
    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)
    create_db(args.max_projects, args.days_to_analyse, args.output_dir,
              args.input_dir, args.base_offset, args.cleanup, args.since_date,
              args.use_gh_cache, args.use_webapp_cache)


if __name__ == "__main__":
    main()
