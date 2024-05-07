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

import constants
import oss_fuzz

DB_JSON_DB_TIMESTAMP = 'db-timestamps.json'
DB_JSON_ALL_PROJECT_TIMESTAMP = 'all-project-timestamps.json'
DB_JSON_ALL_FUNCTIONS = 'all-functions-db.json'
DB_JSON_ALL_CURRENT_FUNCS = 'all-project-current.json'
DB_JSON_ALL_BRANCH_BLOCKERS = 'all-branch-blockers.json'
DB_BUILD_STATUS_JSON = 'build-status.json'
#DB_RAW_INTROSPECTOR_REPORTS = 'raw-introspector-reports'

ALL_JSON_FILES = [
    DB_JSON_DB_TIMESTAMP,
    DB_JSON_ALL_PROJECT_TIMESTAMP,
    DB_JSON_ALL_FUNCTIONS,
    DB_JSON_ALL_CURRENT_FUNCS,
]

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
        logger.info("Timed out cloning %s" % (github_url))
        return False
    except subprocess.CalledProcessError:
        logger.info("Error cloning %s" % (github_url))
        return False
    return True


def rename_annotated_cfg(original_annotated_cfg):
    """Renames an annotated CFG as it is from introspector."""
    new_annotated_cfg = list()
    for fuzzer_name in original_annotated_cfg:
        elem = {
            'fuzzer_name': fuzzer_name,
            'source_file': original_annotated_cfg[fuzzer_name]['src_file'],
            'destinations': []
        }
        for dest_elem in original_annotated_cfg[fuzzer_name]['destinations']:
            refined_dest_elem = dict()
            for k, v in dest_elem.items():
                refined_dest_elem[k.replace("-", "_")] = v
            elem['destinations'].append(refined_dest_elem)

        new_annotated_cfg.append(elem)
    return new_annotated_cfg


def save_fuzz_introspector_report(introspector_report, project_name, date_str):
    # Disable for now to avoid growing the disk too much
    #os.makedirs(DB_RAW_INTROSPECTOR_REPORTS, exist_ok=True)

    #report_dst = os.path.join(DB_RAW_INTROSPECTOR_REPORTS,
    #                          '%s-%s.json' % (project_name, date_str))
    #with open(report_dst, 'w') as report_fd:
    #    json.dump(introspector_report, report_fd)
    return


def save_debug_report(debug_report, project_name):
    project_db_dir = os.path.join(constants.DB_PROJECT_DIR, project_name)
    os.makedirs(project_db_dir, exist_ok=True)

    report_dst = os.path.join(project_db_dir, 'debug_report.json')
    with open(report_dst, 'w') as report_fd:
        json.dump(debug_report, report_fd)


def save_branch_blockers(branch_blockers, project_name):
    project_db_dir = os.path.join(constants.DB_PROJECT_DIR, project_name)
    os.makedirs(project_db_dir, exist_ok=True)

    report_dst = os.path.join(project_db_dir, 'branch_blockers.json')
    with open(report_dst, 'w') as report_fd:
        json.dump(branch_blockers, report_fd)


def save_type_map(debug_report, project_name):
    project_db_dir = os.path.join(constants.DB_PROJECT_DIR, project_name)
    os.makedirs(project_db_dir, exist_ok=True)

    report_dst = os.path.join(project_db_dir, 'type_map.json')
    with open(report_dst, 'w') as report_fd:
        json.dump(debug_report, report_fd)


def extract_and_refine_branch_blockers(introspector_report, project_name):
    branch_pairs = list()
    for key in introspector_report:
        if key == "MergedProjectProfile" or key == 'analyses':
            continue

        # Fuzzer-specific dictionary, get the contents of it.
        val = introspector_report[key]
        if not isinstance(val, dict):
            continue

        branch_blockers = val.get('branch_blockers', None)
        if branch_blockers == None or not isinstance(branch_blockers, list):
            continue

        for branch_blocker in branch_blockers:
            function_blocked = branch_blocker.get('function_name', None)
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
    return branch_pairs


def extract_and_refine_annotated_cfg(introspector_report):
    annotated_cfg = dict()
    for key in introspector_report:
        # We look for dicts with fuzzer-specific content. The following two
        # are not such keys, so skip them.
        if key == 'analyses':
            if 'AnnotatedCFG' in introspector_report[key]:
                annotated_cfg = rename_annotated_cfg(
                    introspector_report['analyses']['AnnotatedCFG'])
    return annotated_cfg


def extract_and_refine_functions(all_function_list, project_name, date_str):
    refined_proj_list = []

    for func in all_function_list:
        introspector_func = {
            'name':
            func['Func name'],
            'code_coverage_url':
            func['func_url'].replace(
                "https://storage.googleapis.com/oss-fuzz-coverage/", ""),
            'filename':
            func['Functions filename'],
            'code_cov':
            float(func['Func lines hit %'].replace("%", "")),
            'is_reached':
            len(func['Reached by Fuzzers']) > 0,
            'reached-by-fuzzers':
            func['Reached by Fuzzers'],
            'project':
            project_name,
            'acc_cc':
            func['Accumulated cyclomatic complexity'],
            'instr-count':
            func['I Count'],
            'u-cc':
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
            date_str,
            'source_line_begin':
            func.get('source_line_begin', 'N/A'),
            'source_line_end':
            func.get('source_line_end', 'N/A'),
            'callsites':
            func.get('callsites', [])
        }

        introspector_func['function-signature'] = func.get(
            'function_signature', 'N/A')
        introspector_func['debug-function'] = func.get('debug_function_info',
                                                       dict())
        introspector_func['is_accessible'] = func.get('is_accessible', True)
        introspector_func['is_jvm_library'] = func.get('is_jvm_library', False)
        introspector_func['is_enum_class'] = func.get('is_enum_class', False)

        refined_proj_list.append(introspector_func)
    return refined_proj_list


def extract_code_coverage_data(code_coverage_summary, project_name, date_str,
                               project_language):
    # Extract data from the code coverage reports
    if code_coverage_summary == None:
        return None

    try:
        line_total_summary = code_coverage_summary['data'][0]['totals'][
            'lines']
    except KeyError:
        # This can happen in Python, where the correct code formatting was only done
        # May 3rd 2023: https://github.com/google/oss-fuzz/pull/10201
        return None
    #line_total_summary['percent']
    # For the sake of consistency, we re-calculate the percentage. This is because
    # some of the implentations have a value 0 <= p <= 1 and some have 0 <= p <= 100.
    try:
        line_total_summary['percent'] = round(
            100.0 * (float(line_total_summary['covered']) /
                     float(line_total_summary['count'])), 2)
    except:
        pass

    coverage_url = oss_fuzz.get_coverage_report_url(project_name,
                                                    date_str.replace("-", ""),
                                                    project_language)
    code_coverage_data_dict = {
        'coverage_url': coverage_url,
        'line_coverage': line_total_summary
    }
    return code_coverage_data_dict


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
        project_language = oss_fuzz.try_to_get_project_language(project_name)
        if project_language == 'jvm':
            project_language = 'java'
    except:
        # Default set to c++ as this is OSS-Fuzz's default.
        project_language = 'c++'

    collect_debug_info = project_language in {'c', 'c++'}

    # Extract code coverage and introspector reports.
    code_coverage_summary = oss_fuzz.get_code_coverage_summary(
        project_name, date_str.replace("-", ""))
    cov_fuzz_stats = oss_fuzz.get_fuzzer_stats_fuzz_count(
        project_name, date_str.replace("-", ""))

    # Get introspector reports for languages with introspector support
    if project_language in {'c', 'c++', 'python', 'java'}:
        introspector_report = oss_fuzz.extract_introspector_report(
            project_name, date_str)
    else:
        introspector_report = None

    introspector_report_url = oss_fuzz.get_introspector_report_url_report(
        project_name, date_str.replace("-", ""))

    # Collet debug informaiton for languages with debug information
    if collect_debug_info:
        introspector_type_map = oss_fuzz.get_introspector_type_map(
            project_name, date_str.replace("-", ""))
    else:
        introspector_type_map = None

    #print("Type mapping:")
    if should_include_details and introspector_type_map:
        # Remove the friendly types from the type map because they take up
        # too much space. Instead, extract this at runtime when it need to be used.
        for addr, value in introspector_type_map.items():
            if 'friendly-info' in value:
                del value['friendly-info']

        # Remove the raw_debug_info from the type
        for addr in introspector_type_map:
            if 'raw_debug_info' in introspector_type_map[addr]:
                introspector_type_map[addr] = introspector_type_map[addr][
                    'raw_debug_info']

                if len(introspector_type_map[addr].get('enum_elems', [])) == 0:
                    del introspector_type_map[addr]['enum_elems']
                if 'type_idx' in introspector_type_map[addr]:
                    del introspector_type_map[addr]['type_idx']

        save_type_map(introspector_type_map, project_name)
    #    for addr in introspector_type_map:
    #        print("Addr: %s"%(str(addr)))

    # Save the report
    save_fuzz_introspector_report(introspector_report, project_name, date_str)

    # Get debug data
    if collect_debug_info and should_include_details:
        debug_report = oss_fuzz.extract_introspector_debug_info(
            project_name, date_str)
        save_debug_report(debug_report, project_name)
    else:
        debug_report = None

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

        # Get details if needed and otherwise leave empty
        refined_proj_list = list()
        branch_pairs = list()
        annotated_cfg = dict()
        if should_include_details:
            refined_proj_list = extract_and_refine_functions(
                all_function_list, project_name, date_str)
            annotated_cfg = extract_and_refine_annotated_cfg(
                introspector_report)
            branch_pairs = extract_and_refine_branch_blockers(
                introspector_report, project_name)

        # Dump things we dont want to accummulate.
        save_branch_blockers(branch_pairs, project_name)

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
            'annotated_cfg': annotated_cfg,
        }

    code_coverage_data_dict = extract_code_coverage_data(
        code_coverage_summary, project_name, date_str, project_language)

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


def extend_func_db(function_list, output_directory):
    if os.path.isfile(os.path.join(output_directory, DB_JSON_ALL_FUNCTIONS)):
        with open(os.path.join(output_directory, DB_JSON_ALL_FUNCTIONS),
                  'r') as f:
            existing_function_list = json.load(f)
    else:
        existing_function_list = []

    # We should update data on all projects where we have function data, and
    # for those we do not have updated information on we will use the old data.
    projects_that_need_updating = set()
    for elem in function_list:
        projects_that_need_updating.add(elem['project'])

    functions_to_keep = []
    for func in existing_function_list:
        if func['project'] not in projects_that_need_updating:
            functions_to_keep.append(func)

    # Add new functions
    all_functions = functions_to_keep + function_list

    with open(os.path.join(output_directory, DB_JSON_ALL_FUNCTIONS), 'w') as f:
        json.dump(all_functions, f)


def update_db_files(db_timestamp, project_timestamps, function_list,
                    output_directory, should_include_details):
    logger.info(
        "Updating the database with DB snapshot. Number of functions in total: %d"
        % (db_timestamp['function_count']))
    if should_include_details:
        extend_func_db(function_list, output_directory)

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

        # Disable for now to avoid growing disk
        # ZIP the archived introspector reports
        #shutil.make_archive(DB_RAW_INTROSPECTOR_REPORTS, 'zip',
        #                    DB_RAW_INTROSPECTOR_REPORTS)

    # Disable for now to avoid growing disk
    # Cleanup DB_RAW_INTROSPECTOR_REPORTS
    #if os.path.isdir(DB_RAW_INTROSPECTOR_REPORTS):
    #    shutil.rmtree(DB_RAW_INTROSPECTOR_REPORTS)


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


def analyse_set_of_dates(dates, projects_to_analyse, output_directory,
                         force_creation):
    """Pe/rforms analysis of all projects in the projects_to_analyse argument for
    the given set of dates. DB .json files are stored in output_directory.
    """
    idx = 1
    for date in dates:
        current_time = datetime.datetime.now().strftime("%H:%M:%S")
        logger.info("Analysing date %s -- [%d of %d] -- %s" %
                    (date, idx, len(dates), current_time))

        # Is this the last date to analyse?
        is_end = idx == len(dates)
        logger.info("Is this the last date: %s" % (is_end))

        # Increment counter. Must happen after our is_end check.
        idx += 1

        # If it's not the last date and we have cached data, use the cache.
        if not force_creation and is_end == False and is_date_in_db(
                date, output_directory):
            logger.info("Date already analysed, skipping")
            continue

        if force_creation:
            is_end = True

        function_list, project_timestamps, db_timestamp = analyse_list_of_projects(
            date, projects_to_analyse, should_include_details=is_end)
        update_db_files(db_timestamp,
                        project_timestamps,
                        function_list,
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

    logger.info("The input dir: %s" % (input_dir))
    if not os.path.isdir(input_dir):
        raise Exception("No input directory, but specified")

    if not os.path.isdir(output_dir):
        os.mkdir(output_dir)

    for f in ALL_JSON_FILES:
        if os.path.isfile(os.path.join(input_dir, f)):
            shutil.copyfile(os.path.join(input_dir, f),
                            os.path.join(output_dir, f))


def prepare_output_folder(input_directory, output_directory):
    """Makes output folder ready for analysis."""

    # Copy input cache to output so analysis from current state.
    if input_directory is not None:
        copy_input_to_output(input_directory, output_directory)

    if not os.path.isdir(output_directory):
        os.mkdir(output_directory)


def extract_oss_fuzz_build_status(output_directory):
    """Extracts fuzz/coverage/introspector build status from OSS-Fuzz stats."""
    # Extract the build status of all OSS-Fuzz projects
    # Create a local clone of OSS-Fuzz. This is used for checking language of a project easily.
    oss_fuzz_local_clone = os.path.join(output_directory,
                                        constants.OSS_FUZZ_CLONE)
    if os.path.isdir(oss_fuzz_local_clone):
        shutil.rmtree(oss_fuzz_local_clone)
    git_clone_project(constants.OSS_FUZZ_REPO, oss_fuzz_local_clone)

    build_status_dict = oss_fuzz.get_projects_build_status()
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

    git_clone_project(constants.OSS_FUZZ_GITHUB_BACKUP_REPO, "github_cache")
    if not os.path.isdir("github_cache"):
        return False
    db_zipfile = os.path.join("github_cache", "db-stamp.zip")
    if os.path.isfile(db_zipfile):
        with zipfile.ZipFile(db_zipfile, 'r') as zip_ref:
            zip_ref.extractall("github_cache")
        return True
    return False


def setup_webapp_cache():
    logger.info("Getting the db archive")
    r = requests.get(INTROSPECTOR_WEBAPP_ZIP, stream=True)
    db_archive = zipfile.ZipFile(io.BytesIO(r.content))

    if os.path.isdir("extracted-db-archive"):
        shutil.rmtree("extracted-db-archive")
    os.mkdir("extracted-db-archive")

    db_archive.extractall("extracted-db-archive")
    logger.info("Extracted it all")

    # Copy over the files
    shutil.copyfile(os.path.join("extracted-db-archive", DB_JSON_DB_TIMESTAMP),
                    DB_JSON_DB_TIMESTAMP)
    shutil.copyfile(
        os.path.join("extracted-db-archive", DB_JSON_ALL_PROJECT_TIMESTAMP),
        DB_JSON_ALL_PROJECT_TIMESTAMP)

    # If we get to here it all went well.


def reduce_projects_to_analyse(projects_to_analyse, max_projects,
                               includes_file):
    must_include = set()
    if includes_file is not None:
        with open(includes_file, "r") as f:
            for line in f:
                if line.strip():
                    must_include.add(line.strip())

    if max_projects > 0 and len(projects_to_analyse) > max_projects:
        tmp_dictionary = dict()
        idx = 0
        for k in projects_to_analyse:
            for p in must_include:
                if p in k:
                    tmp_dictionary[k] = projects_to_analyse[k]

        for k in projects_to_analyse:
            if idx > max_projects:
                break
            tmp_dictionary[k] = projects_to_analyse[k]
            idx += 1
        projects_to_analyse = tmp_dictionary

    logger.info("Projects targeted in the DB creation")
    for p in projects_to_analyse:
        logger.info("- %s" % (p))
    return projects_to_analyse


def create_cache(use_webapp_cache, use_github_cache, input_directory,
                 output_directory):
    got_cache = False
    if use_webapp_cache:
        try:
            setup_webapp_cache()
            # If we got to here, that means the cache download went well.
            got_cache = True
        except:
            got_cache = False

    if use_github_cache and not got_cache:
        if setup_github_cache():
            input_directory = "github_cache"
        else:
            logger.info("Could not create Github cache")

    # Create folders we will
    prepare_output_folder(input_directory, output_directory)

    # Cleanup github
    if os.path.isdir("github_cache"):
        shutil.rmtree("github_cache")

    return input_directory


def get_dates_to_analyse(since_date, days_to_analyse, day_offset):
    if since_date != None:
        start_date = datetime.datetime.strptime(since_date, "%d-%m-%Y").date()
        today = datetime.date.today()
        delta = today - start_date
        days_to_analyse = delta.days - 1
        day_offset = 0
    date_range = create_date_range(day_offset, days_to_analyse)

    return date_range


def create_db(max_projects, days_to_analyse, output_directory, input_directory,
              day_offset, to_cleanup, since_date, use_github_cache,
              use_webapp_cache, force_creation, includes_file):

    # Set up cache and input/output directory
    input_directory = create_cache(use_webapp_cache, use_github_cache,
                                   input_directory, output_directory)

    # Get latest build statuses from OSS-Fuzz and use this to guide which
    # projects to analyze.
    projects_list_build_status = extract_oss_fuzz_build_status(
        output_directory)
    projects_to_analyse = dict()
    for p in projects_list_build_status:
        projects_to_analyse[p] = projects_list_build_status[p]

    # Reduce the amount of projects if needed.
    projects_to_analyse = reduce_projects_to_analyse(projects_to_analyse,
                                                     max_projects,
                                                     includes_file)

    if to_cleanup:
        cleanup(output_directory)

    date_range = get_dates_to_analyse(since_date, days_to_analyse, day_offset)
    logger.info("Creating a DB with the specifications:")
    logger.info("- Date range: [%s : %s]" %
                (str(date_range[0]), str(date_range[-1])))
    logger.info("- Total of %d projects to analyse" %
                (len(projects_to_analyse)))
    if input_directory is not None:
        logger.info("- Extending upon the DB in %s" % (str(input_directory)))
    else:
        logger.info("-Creating the DB from scratch")

    logger.info("Starting analysis of max %d projects" %
                (len(projects_to_analyse)))

    analyse_set_of_dates(date_range, projects_to_analyse, output_directory,
                         force_creation)


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
    parser.add_argument(
        "--includes",
        help=
        "File with names of projects (line separated) that must be included in the DB",
        default=None)
    parser.add_argument("--cleanup", action="store_true")
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--use_gh_cache", action="store_false")
    parser.add_argument("--use_webapp_cache", action="store_true")
    parser.add_argument("--force-creation", action="store_true")
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
              args.use_gh_cache, args.use_webapp_cache, args.force_creation,
              args.includes)


if __name__ == "__main__":
    main()
