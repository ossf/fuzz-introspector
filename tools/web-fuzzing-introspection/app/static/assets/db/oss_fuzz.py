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
"""Utilities for getting data from OSS-Fuzz"""

import os
import json
import yaml
import requests

import constants


def get_introspector_report_url_base(project_name, datestr):
    base_url = 'https://storage.googleapis.com/oss-fuzz-introspector/{0}/inspector-report/{1}/'
    project_url = base_url.format(project_name, datestr)
    return project_url


def get_introspector_report_url_summary(project_name, datestr):
    return get_introspector_report_url_base(project_name,
                                            datestr) + "summary.json"


def get_introspector_report_url_branch_blockers(project_name, datestr):
    return get_introspector_report_url_base(project_name,
                                            datestr) + "branch-blockers.json"


def get_introspector_report_url_all_functions(project_name, datestr):
    return get_introspector_report_url_base(
        project_name, datestr) + "all-fuzz-introspector-functions.json"


def get_introspector_report_url_jvm_constructor(project_name, datestr):
    return get_introspector_report_url_base(
        project_name, datestr) + "all-fuzz-introspector-jvm-constructor.json"


def get_introspector_report_url_report(project_name, datestr):
    return get_introspector_report_url_base(project_name,
                                            datestr) + "fuzz_report.html"


def get_introspector_report_url_typedef(project_name,
                                        datestr,
                                        second_run=False):
    base = get_introspector_report_url_base(project_name, datestr)
    if second_run:
        base += "second-frontend-run/"
    return base + "full_type_defs.json"


def get_introspector_report_url_macro_block(project_name,
                                            datestr,
                                            second_run=False):
    base = get_introspector_report_url_base(project_name, datestr)
    if second_run:
        base += "second-frontend-run/"
    return base + "macro_block_info.json"


def get_fuzzer_stats_fuzz_count_url(project_name, date_str):
    base_url = 'https://storage.googleapis.com/oss-fuzz-coverage/{0}/fuzzer_stats/{1}/coverage_targets.txt'
    coverage_targets = base_url.format(project_name, date_str)
    return coverage_targets


def get_fuzzer_target_coverage_error_log_url(project_name, date_str, target):
    '''Get the url for the potential errors that are encountered during coverage measurement of a target.
    Note that if the file does not exist, no errors have been recorded.'''
    base_url = 'https://storage.googleapis.com/oss-fuzz-coverage/{0}/fuzzer_stats/{1}/{2}_error.log'
    url = base_url.format(project_name, date_str, target)
    return url


def get_introspector_project_tests_url(project_name, datestr):
    return get_introspector_report_url_base(project_name,
                                            datestr) + "light/all_tests.json"


def get_introspector_project_tests_xref_url(project_name, datestr):
    return get_introspector_report_url_base(
        project_name, datestr) + "all_tests_with_xreference.json"


def get_introspector_project_all_files(project_name, datestr):
    return get_introspector_report_url_base(project_name,
                                            datestr) + "light/all_files.json"


def get_introspector_light_pairs_url(project_name, datestr):
    return get_introspector_report_url_base(project_name,
                                            datestr) + "light/all_pairs.json"


def extract_introspector_light_all_pairs(project_name, date_str):
    """Gets the list of pairs from introspector light"""
    debug_data_url = get_introspector_light_pairs_url(
        project_name, date_str.replace("-", ""))
    try:
        raw_introspector_json_request = requests.get(debug_data_url,
                                                     timeout=10)
    except:
        return []
    try:
        all_pairs = json.loads(raw_introspector_json_request.text)
    except:
        return []

    return all_pairs


def get_introspector_light_tests_url(project_name, datestr):
    return get_introspector_report_url_base(project_name,
                                            datestr) + "light/all_tests.json"


def extract_introspector_light_all_tests(project_name, date_str):
    """Gets the list of test files from light"""
    debug_data_url = get_introspector_light_tests_url(
        project_name, date_str.replace("-", ""))
    try:
        raw_introspector_json_request = requests.get(debug_data_url,
                                                     timeout=10)
    except:
        return []
    try:
        all_tests = json.loads(raw_introspector_json_request.text)
    except:
        return []

    return all_tests


def get_introspector_light_all_files_url(project_name, datestr):
    return get_introspector_report_url_base(project_name,
                                            datestr) + "light/all_files.json"


def extract_introspector_light_all_files(project_name, date_str):
    """Gets the list of all files from light"""
    debug_data_url = get_introspector_light_all_files_url(
        project_name, date_str.replace("-", ""))
    try:
        raw_introspector_json_request = requests.get(debug_data_url,
                                                     timeout=10)
    except:
        return []
    try:
        all_urls = json.loads(raw_introspector_json_request.text)
    except:
        return []

    return all_urls


def extract_introspector_branch_blockers(project_name, date_str):
    introspector_branch_blockers_url = get_introspector_report_url_branch_blockers(
        project_name, date_str.replace("-", ""))

    # Read the introspector atifact
    try:
        raw_introspector_json_request = requests.get(
            introspector_branch_blockers_url, timeout=10)
    except:
        return None
    try:
        branch_blockers = json.loads(raw_introspector_json_request.text)
    except:
        return None

    return branch_blockers


def get_introspector_type_map_url_summary(project_name, datestr):
    return get_introspector_report_url_base(
        project_name, datestr) + "all-friendly-debug-types.json"


def get_fuzzer_stats_fuzz_count(project_name, date_str):
    coverage_stats_url = get_fuzzer_stats_fuzz_count_url(
        project_name, date_str)
    try:
        coverage_summary_raw = requests.get(coverage_stats_url,
                                            timeout=20).text
    except:
        return None

    if "The specified key does not exist" in coverage_summary_raw:
        return None
    return coverage_summary_raw


def get_code_coverage_summary_url(project_name, datestr):
    base_url = 'https://storage.googleapis.com/oss-fuzz-coverage/{0}/reports/{1}/linux/summary.json'
    project_url = base_url.format(project_name, datestr)
    return project_url


def get_fuzzer_code_coverage_summary_url(project_name, datestr, fuzzer):
    base_url = 'https://storage.googleapis.com/oss-fuzz-coverage/{0}/reports-by-target/{1}/{2}/linux/summary.json'
    project_url = base_url.format(project_name, datestr, fuzzer)
    return project_url


def get_coverage_report_url(project_name, datestr, language):
    if language == 'java' or language == 'python' or language == 'go':
        file_report = "index.html"
    else:
        file_report = "report.html"
    base_url = 'https://storage.googleapis.com/oss-fuzz-coverage/{0}/reports/{1}/linux/{2}'
    project_url = base_url.format(project_name, datestr, file_report)
    return project_url


def get_introspector_report_url_debug_info(project_name, datestr):
    return get_introspector_report_url_base(project_name,
                                            datestr) + "all_debug_info.json"


def get_introspector_report_url_fuzzer_log_file(project_name, datestr, fuzzer):
    return get_introspector_report_url_base(
        project_name, datestr) + f"fuzzerLogFile-{fuzzer}.data.yaml"


def get_introspector_report_url_fuzzer_program_data(project_name, datestr,
                                                    program_data_filename):
    return get_introspector_report_url_base(project_name,
                                            datestr) + program_data_filename


def get_introspector_report_url_fuzzer_coverage_urls(project_name, datestr,
                                                     coverage_files):
    prefix = get_introspector_report_url_base(project_name, datestr)
    return [prefix + ff for ff in coverage_files]


def extract_introspector_debug_info(project_name, date_str):
    debug_data_url = get_introspector_report_url_debug_info(
        project_name, date_str.replace("-", ""))
    #print("Getting: %s" % (introspector_summary_url))
    # Read the introspector atifact
    try:
        raw_introspector_json_request = requests.get(debug_data_url,
                                                     timeout=10)
    except:
        return dict()
    try:
        debug_report = json.loads(raw_introspector_json_request.text)
    except:
        return dict()

    return debug_report


def extract_local_introspector_function_list(project_name, oss_fuzz_folder):
    summary_json = os.path.join(oss_fuzz_folder, 'build', 'out', project_name,
                                'inspector',
                                'all-fuzz-introspector-functions.json')
    if not os.path.isfile(summary_json):
        return []

    with open(summary_json, 'r') as f:
        function_list = json.load(f)
    return function_list


def extract_local_introspector_branch_blockers(project_name, oss_fuzz_folder):
    summary_json = os.path.join(oss_fuzz_folder, 'build', 'out', project_name,
                                'inspector', 'branch-blockers.json')
    if not os.path.isfile(summary_json):
        return {}
    with open(summary_json, 'r') as f:
        json_dict = json.load(f)
    return json_dict


def extract_local_introspector_constructor_list(project_name, oss_fuzz_folder):
    summary_json = os.path.join(oss_fuzz_folder, 'build', 'out', project_name,
                                'inspector',
                                'all-fuzz-introspector-jvm-constructor.json')
    if not os.path.isfile(summary_json):
        return []

    with open(summary_json, 'r') as f:
        function_list = json.load(f)
    return function_list


def extract_local_introspector_report(project_name, oss_fuzz_folder):
    summary_json = os.path.join(oss_fuzz_folder, 'build', 'out', project_name,
                                'inspector', 'summary.json')
    if not os.path.isfile(summary_json):
        return {}

    with open(summary_json, 'r') as f:
        json_dict = json.load(f)
    return json_dict


def extract_local_introspector_typedef(project_name, oss_fuzz_folder):
    json_base = os.path.join(oss_fuzz_folder, 'build', 'out', project_name,
                             'inspector')

    summary_json = os.path.join(json_base, 'full_type_defs.json')
    if not os.path.isfile(summary_json):
        # Failed to locate the json in first introspector run
        # Possibly run from LTO, try locate the file in second introspector run
        summary_json = os.path.join(json_base, 'second-frontend-run',
                                    'full_type_defs.json')
        if not os.path.isfile(summary_json):
            return {}

    with open(summary_json, 'r') as f:
        json_list = json.load(f)
    return json_list


def extract_local_introspector_macro_block(project_name, oss_fuzz_folder):
    json_base = os.path.join(oss_fuzz_folder, 'build', 'out', project_name,
                             'inspector')

    summary_json = os.path.join(json_base, 'macro_block_info.json')
    if not os.path.isfile(summary_json):
        # Failed to locate the json in first introspector run
        # Possibly run from LTO, try locate the file in second introspector run
        summary_json = os.path.join(json_base, 'second-frontend-run',
                                    'macro_block_info.json')
        if not os.path.isfile(summary_json):
            return {}

    with open(summary_json, 'r') as f:
        json_list = json.load(f)
    return json_list


def get_local_code_coverage_summary(project_name, oss_fuzz_folder):
    summary_json = os.path.join(oss_fuzz_folder, 'build', 'out', project_name,
                                'report', 'linux', 'summary.json')
    if not os.path.isfile(summary_json):
        return None
    with open(summary_json, 'r') as f:
        json_dict = json.load(f)
    return json_dict


def get_local_code_coverage_stats(project_name, oss_fuzz_folder):
    coverage_targets = os.path.join(oss_fuzz_folder, 'build', 'out',
                                    project_name, 'fuzzer_stats',
                                    'coverage_targets.txt')
    if not os.path.isfile(coverage_targets):
        return None
    with open(coverage_targets, 'r') as f:
        content = f.read()
    return content


def get_code_coverage_summary(project_name, datestr):
    cov_summary_url = get_code_coverage_summary_url(project_name, datestr)
    try:
        coverage_summary_raw = requests.get(cov_summary_url, timeout=20).text
    except:
        return None
    try:
        json_dict = json.loads(coverage_summary_raw)
        return json_dict
    except:
        return None


def get_fuzzer_code_coverage_summary(project_name, datestr, fuzzer):
    cov_summary_url = get_fuzzer_code_coverage_summary_url(
        project_name, datestr, fuzzer)
    try:
        coverage_summary_raw = requests.get(cov_summary_url, timeout=20).text
    except:
        return None
    try:
        json_dict = json.loads(coverage_summary_raw)
        return json_dict
    except:
        return None


def get_fuzzer_target_coverage_error_log(project_name, datestr, fuzzer):
    url = get_fuzzer_target_coverage_error_log_url(project_name, datestr,
                                                   fuzzer)
    try:
        response = requests.get(url, timeout=20)
        if response.status_code == 200:
            return response.text.strip()
    except Exception as e:
        return None


MAGNITUDES = {
    "k": 10**(3 * 1),
    "M": 10**(3 * 2),
    "G": 10**(3 * 3),
    "T": 10**(3 * 4),
    "P": 10**(3 * 5),
    "E": 10**(3 * 6),
    "Z": 10**(3 * 7),
    "Y": 10**(3 * 8),
}


def get_fuzzer_corpus_size(project_name, datestr, fuzzer, introspector_report):
    """Go through coverage reports to find the LLVMFuzzerTestOneInput function. The first hit count equals the number inputs found."""

    if introspector_report["MergedProjectProfile"]["overview"][
            "language"] != "c-cpp":
        return None

    metadata_files = introspector_report[fuzzer]["metadata-files"]

    fuzzer_program_coverage_urls = get_introspector_report_url_fuzzer_coverage_urls(
        project_name, datestr, metadata_files["coverage"])

    for url in fuzzer_program_coverage_urls:
        found = False
        try:
            cov_res = requests.get(url, timeout=20).text
            for ll in cov_res.splitlines():
                if found:
                    # Letters used is implemented here:
                    # https://github.com/llvm/llvm-project/blob/7569de527298a52618239ef68b9374a5c35c8b97/llvm/tools/llvm-cov/SourceCoverageView.cpp#L117
                    # Used from here:
                    # https://github.com/llvm/llvm-project/blob/35ed9a32d58bc8cbace31dc7c3bba79d0e3a9256/llvm/tools/llvm-cov/SourceCoverageView.h#L269
                    try:
                        count_str = ll.split("|")[1].strip()
                        magnitude_char = count_str[-1]
                        if magnitude_char.isalpha():
                            magnitude = MAGNITUDES[magnitude_char]
                            count = float(count_str[:-1])
                        else:
                            magnitude = 1
                            count = float(count_str)
                        return int(magnitude * count)
                    except:
                        # Something went wrong, maybe another file has correct data.
                        break
                if ll == "LLVMFuzzerTestOneInput:":
                    found = True
        except:
            return None


def extract_new_introspector_functions(project_name, date_str):
    introspector_functions_url = get_introspector_report_url_all_functions(
        project_name, date_str.replace("-", ""))

    # Read the introspector artifact
    try:
        raw_introspector_json_request = requests.get(
            introspector_functions_url, timeout=10)
        introspector_functions = json.loads(raw_introspector_json_request.text)
    except:
        return []

    return introspector_functions


def extract_new_introspector_constructors(project_name, date_str):
    introspector_constructor_url = get_introspector_report_url_jvm_constructor(
        project_name, date_str.replace("-", ""))

    # Read the introspector artifact
    try:
        raw_introspector_json_request = requests.get(
            introspector_constructor_url, timeout=10)
        introspector_constructors = json.loads(
            raw_introspector_json_request.text)
    except:
        return []

    return introspector_constructors


def extract_introspector_all_files(project_name, date_str):
    introspector_all_files_url = get_introspector_project_all_files(
        project_name, date_str.replace("-", ""))

    # Read the introspector atifact
    try:
        raw_introspector_json_request = requests.get(
            introspector_all_files_url, timeout=10)
    except:
        return None
    try:
        all_files = json.loads(raw_introspector_json_request.text)
    except:
        return None

    return all_files


def extract_introspector_test_files(project_name, date_str):
    introspector_test_url = get_introspector_project_tests_url(
        project_name, date_str.replace("-", ""))

    # Read the introspector atifact
    try:
        raw_introspector_json_request = requests.get(introspector_test_url,
                                                     timeout=10)
    except:
        return None
    try:
        test_files = json.loads(raw_introspector_json_request.text)
    except:
        return None

    return test_files


def extract_introspector_test_files_xref(project_name, date_str):
    introspector_test_url = get_introspector_project_tests_xref_url(
        project_name, date_str.replace("-", ""))

    # Read the introspector atifact
    try:
        raw_introspector_json_request = requests.get(introspector_test_url,
                                                     timeout=10)
    except:
        return None
    try:
        test_files = json.loads(raw_introspector_json_request.text)
    except:
        return None

    return test_files


def extract_introspector_typedef(project_name, date_str):
    introspector_test_url = get_introspector_report_url_typedef(
        project_name, date_str.replace("-", ""))

    # Read the introspector artifact
    try:
        typedef_list = json.loads(
            requests.get(introspector_test_url, timeout=10).text)

    except:
        # Failed to locate the json in first introspector run
        # Possibly run from LTO, try locate the file in second introspector run
        introspector_test_url = get_introspector_report_url_typedef(
            project_name, date_str.replace("-", ""), True)
        try:
            typedef_list = json.loads(
                requests.get(introspector_test_url, timeout=10).text)
        except:
            return []

    return typedef_list


def extract_introspector_macro_block(project_name, date_str):
    introspector_test_url = get_introspector_report_url_macro_block(
        project_name, date_str.replace("-", ""))

    # Read the introspector atifact
    try:
        return json.loads(requests.get(introspector_test_url, timeout=10).text)
    except:
        # Failed to locate the json in first introspector run
        # Possibly run from LTO, try locate the file in second introspector run
        introspector_test_url = get_introspector_report_url_macro_block(
            project_name, date_str.replace("-", ""), True)
        try:
            return json.loads(
                requests.get(introspector_test_url, timeout=10).text)
        except:
            return []

    return []


def extract_introspector_report(project_name, date_str):
    introspector_summary_url = get_introspector_report_url_summary(
        project_name, date_str.replace("-", ""))
    introspector_report_url = get_introspector_report_url_report(
        project_name, date_str.replace("-", ""))

    # Read the introspector artifact
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


def extract_local_introspector_all_files(project_name, oss_fuzz_folder):
    summary_json = os.path.join(oss_fuzz_folder, 'build', 'out', project_name,
                                'inspector', 'all-files.json')
    if not os.path.isfile(summary_json):
        return []
    with open(summary_json, 'r') as f:
        json_list = json.load(f)
    return json_list


def extract_local_introspector_test_files(project_name, oss_fuzz_folder):
    summary_json = os.path.join(oss_fuzz_folder, 'build', 'out', project_name,
                                'inspector', 'test-files.json')
    if not os.path.isfile(summary_json):
        return {}
    with open(summary_json, 'r') as f:
        json_list = json.load(f)
    return json_list


def extract_local_introspector_test_files_xref(project_name, oss_fuzz_folder):
    summary_json = os.path.join(oss_fuzz_folder, 'build', 'out', project_name,
                                'inspector', 'all_tests_with_xreference.json')
    if not os.path.isfile(summary_json):
        return {}
    with open(summary_json, 'r') as f:
        json_list = json.load(f)
    return json_list


def extract_local_introspector_light_test_files(project_name, oss_fuzz_folder):
    summary_json = os.path.join(oss_fuzz_folder, 'build', 'out', project_name,
                                'inspector', 'light', 'all_tests.json')
    if not os.path.isfile(summary_json):
        return {}
    with open(summary_json, 'r') as f:
        json_list = json.load(f)
    return json_list


def extract_local_introspector_light_pairs(project_name, oss_fuzz_folder):
    summary_json = os.path.join(oss_fuzz_folder, 'build', 'out', project_name,
                                'inspector', 'light', 'all_pairs.json')
    if not os.path.isfile(summary_json):
        return {}
    with open(summary_json, 'r') as f:
        json_list = json.load(f)
    return json_list


def extract_local_introspector_light_all_files(project_name, oss_fuzz_folder):
    summary_json = os.path.join(oss_fuzz_folder, 'build', 'out', project_name,
                                'inspector', 'light', 'all_files.json')
    if not os.path.isfile(summary_json):
        return {}
    with open(summary_json, 'r') as f:
        json_list = json.load(f)
    return json_list


def extract_local_introspector_debug_info(project_name, oss_fuzz_folder):
    summary_json = os.path.join(oss_fuzz_folder, 'build', 'out', project_name,
                                'inspector', 'all_debug_info.json')
    if not os.path.isfile(summary_json):
        return {}
    with open(summary_json, 'r') as f:
        json_dict = json.load(f)
    return json_dict


def get_local_introspector_type_map(project_name, oss_fuzz_folder):
    summary_json = os.path.join(oss_fuzz_folder, 'build', 'out', project_name,
                                'inspector', 'all-friendly-debug-types.json')
    if not os.path.isfile(summary_json):
        return {}
    with open(summary_json, 'r') as f:
        json_dict = json.load(f)
    return json_dict


def get_introspector_type_map(project_name, date_str):
    introspector_type_api_url = get_introspector_type_map_url_summary(
        project_name, date_str.replace("-", ""))

    # Read the introspector atifact
    try:
        raw_introspector_json_request = requests.get(introspector_type_api_url,
                                                     timeout=10)
    except:
        return None
    try:
        introspector_type_map = json.loads(raw_introspector_json_request.text)
    except:
        return None

    return introspector_type_map


def get_projects_build_status():
    fuzz_build_url = constants.OSS_FUZZ_BUILD_STATUS_URL + '/' + constants.FUZZ_BUILD_JSON
    coverage_build_url = constants.OSS_FUZZ_BUILD_STATUS_URL + '/' + constants.COVERAGE_BUILD_JSON
    introspector_build_url = constants.OSS_FUZZ_BUILD_STATUS_URL + '/' + constants.INTROSPECTOR_BUILD_JSON

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
        project_dict['fuzz-build-log'] = constants.OSS_FUZZ_BUILD_LOG_BASE + p[
            'history'][0]['build_id'] + '.txt'
        build_status_dict[p['name']] = project_dict
    for p in cov_build_json['projects']:
        project_dict = build_status_dict.get(p['name'], dict())

        try:
            project_dict['cov-build'] = p['history'][0]['success']
            project_dict[
                'cov-build-log'] = constants.OSS_FUZZ_BUILD_LOG_BASE + p[
                    'history'][0]['build_id'] + '.txt'
        except (KeyError, IndexError):
            project_dict['cov-build'] = False
            project_dict['cov-build-log'] = 'N/A'

        build_status_dict[p['name']] = project_dict
    for p in introspector_build_json['projects']:
        project_dict = build_status_dict.get(p['name'], dict())
        project_dict['introspector-build'] = p['history'][0]['success']
        project_dict[
            'introspector-build-log'] = constants.OSS_FUZZ_BUILD_LOG_BASE + p[
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
        project_language = try_to_get_project_language(project_name)
        build_status_dict[project_name]['language'] = project_language
    print("Number of projects: %d" % (len(build_status_dict)))
    return build_status_dict


def try_to_get_project_language(project_name):
    if os.path.isdir(constants.OSS_FUZZ_CLONE):
        local_project_path = os.path.join(constants.OSS_FUZZ_CLONE, "projects",
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
        try:
            r = requests.get(proj_yaml_url, timeout=10)
        except:
            return "N/A"
        project_yaml = yaml.safe_load(r.text)
        return project_yaml['language']
    return "N/A"


def try_to_get_project_repository(project_name):
    if os.path.isdir(constants.OSS_FUZZ_CLONE):
        local_project_path = os.path.join(constants.OSS_FUZZ_CLONE, "projects",
                                          project_name)
        if os.path.isdir(local_project_path):
            project_yaml_path = os.path.join(local_project_path,
                                             "project.yaml")
            if os.path.isfile(project_yaml_path):
                with open(project_yaml_path, "r") as f:
                    project_yaml = yaml.safe_load(f.read())
                    return project_yaml['main_repo']
    else:
        proj_yaml_url = 'https://raw.githubusercontent.com/google/oss-fuzz/master/projects/%s/project.yaml' % (
            project_name)
        try:
            r = requests.get(proj_yaml_url, timeout=10)
        except:
            return "N/A"
        project_yaml = yaml.safe_load(r.text)
        return project_yaml['main_repo']
    return "N/A"
