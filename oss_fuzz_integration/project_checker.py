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

import os
import json
import sys
import argparse
import requests

class ProjectCheckError(Exception):
    def __init__(self, message):
        self.message = message

    def __str__(self):
        return self.message

def err_exit(msg):
    raise ProjectCheckError(f"Error {msg}")

def guide_exit(msg):
    msg += (
        "\n Check the data and determine if there is a bug in fuzz-introspecto "
        "or the project changed. Please fix test data or fuzz-introspector accordingly."
    )
    err_exit(msg)

def range_check(value, expected, d):
    return value > (expected - d) and value < (expected + d)

# We write some checkers for each project. This is a bit hacky, but I think it
# can quickly break if we make the data too tight.
def check_project_htslib(summary_dict):
    """Checks summary dict against htslib details"""
    fuzzer_list = []
    for k in summary_dict:
        if k != "MergedProjectProfile":
            fuzzer_list.append(k)
    if len(fuzzer_list) != 1:
        guide_exit("htslib fuzzer count is wrong")
    if fuzzer_list[0] != "hts_open_fuzzer":
        guide_exit("htslib fuzzer name is wrong")

    # check stats
    hts_open_fuzzer = summary_dict['hts_open_fuzzer']
    if hts_open_fuzzer['stats']['total-basic-blocks'] < 25000:
        guide_exit("htslib basic block count seems off.")

    val = hts_open_fuzzer['coverage-blocker-stats']['cov-reach-proportion']
    if not range_check(val, 15.0, 5.0):
        guide_exit("coverage reach proportion seems off.")

    merged_profile = summary_dict['MergedProjectProfile']
    val = merged_profile['stats']['unreached-complexity-percentage']
    if not range_check(val, 35.0, 5.0):
        guide_exit("htslib unreached complexity percentage seems off.")


    # Success
    return


def check_project_jsoncpp(summary_dict):
    """Checks summary dict against htslib details"""
    fuzzer_list = []
    for k in summary_dict:
        if k != "MergedProjectProfile":
            fuzzer_list.append(k)
    if len(fuzzer_list) != 2:
        guide_exit("jsoncpp fuzzer count is wrong")

    jsoncpp_fuzzer_cov_block_stats = summary_dict['jsoncpp_fuzzer']['coverage-blocker-stats']
    if jsoncpp_fuzzer_cov_block_stats['cov-reach-proportion'] < 50.0:
        guide_exit("coverage reach proportion seems off.")

    jsoncpp_proto_fuzzer_cov_block_stats = summary_dict['jsoncpp_proto_fuzzer']['coverage-blocker-stats']
    if jsoncpp_proto_fuzzer_cov_block_stats['cov-reach-proportion'] < 50.0:
        guide_exit("coverage reach proportion seems off.")

    # Success
    return


def check_project_leveldb(summary_dict):
    """Checks leveldb after 10 sec execution"""

    if "fuzz_db" not in summary_dict:
        guide_exit("Did not find fuzz_db in leveldb")
    fuzz_db = summary_dict['fuzz_db']

    if not range_check(fuzz_db['stats']['total-basic-blocks'], 3000, 200):
        guide_exit("Basic block count in leveldb seem off")
    if not range_check(fuzz_db['coverage-blocker-stats']['cov-reach-proportion'], 50.0, 10.0):
        guide_exit("coverage reach proportion in leveldb seem off")



def check_project_unrar(summary_dict):
    """Checks summary dict against htslib details"""
    fuzzer_list = []
    for k in summary_dict:
        if k != "MergedProjectProfile":
            fuzzer_list.append(k)
    if len(fuzzer_list) != 1:
        guide_exit("unrar fuzzer count is wrong")

    cov_block_stats = summary_dict['unrar_fuzzer']['coverage-blocker-stats']
    if cov_block_stats['cov-reach-proportion'] < 10.0:
        guide_exit("coverage reach proportion seems off.")
    if cov_block_stats['cov-reach-proportion'] > 80.0:
        guide_exit("coverage reach proportion seems off.")

    stats = summary_dict['unrar_fuzzer']['stats']
    if stats['file-target-count'] < 40:
        guide_exit("file target count seems off.")

    # Success
    return

def check_specific_project(proj_name, build_log_file,coverage_log,summary_json):
    print(f"Checking {proj_name}")
    name_to_check_mapping = {
        "htslib":  check_project_htslib,
        "jsoncpp": check_project_jsoncpp,
        "unrar":   check_project_unrar,
        "leveldb": check_project_leveldb
    }

    if proj_name not in name_to_check_mapping:
        print("Project cannot be checked. Moving on the next")
        return

    data = json.load(open(summary_json))
    name_to_check_mapping[proj_name](data)
    print("Check done")


def check_project_html_sanity(html_report):
    """Checks the sanity of URLs in the html file. Returns False if fails"""
    with open(html_report, 'r') as html_file:
        for line in html_file:
            line_pos = line.find("<a href")
            if line_pos == -1:
                continue
            url_begin_pos = line.find('"', line_pos)
            url_end_pos = line.find('"', url_begin_pos+1)
            url = line[url_begin_pos+1:url_end_pos]
            if url.startswith("http://") or url.startswith("https://"):
                status = requests.head(url)
                if status.status_code != 200:
                    print("Faulty URL: %s"%url)
                    return False
    return True


def check_project_dir(proj_dir):
    print(f"Checking {proj_dir}")
    build_log_file   = os.path.join(proj_dir, "build_introspector.log")
    coverage_log     = os.path.join(proj_dir, "get_coverage.log")
    summary_json     = os.path.join(proj_dir, "inspector-report", "summary.json")
    proj_name_file   = os.path.join(proj_dir, "project_name")
    html_report      = os.path.join(proj_dir, "inspector-report", "fuzz_report.html")

    if not os.path.isfile(build_log_file):
        err_exit("No log file")
    if not os.path.isfile(coverage_log):
        err_exit("No coverage log")
    if not os.path.isfile(summary_json):
        err_exit("No summary file")
    print(proj_name_file)
    if not os.path.isfile(proj_name_file):
        err_exit("No project name file")
    if not os.path.isfile(html_report):
        err_exit("No html report file")

    if not check_project_html_sanity(html_report):
        err_exit("Html sanity check failed")

    with open(proj_name_file, "r") as pf:
        proj_name = pf.read().replace("\n","")

    # Check summary file
    check_specific_project(
        proj_name,
        build_log_file,
        coverage_log,
        summary_json
    )


def check_test_directory(test_directory):
    proj_dirs = []
    if not os.path.isdir(test_directory):
        err_exit("test directory does not exist")

    for l in os.listdir(test_directory):
        if "corpus-" in l and os.path.isdir(os.path.join(test_directory, l)):
            proj_dirs.append(l)


    for proj_dir in proj_dirs:
        check_project_dir(os.path.join(test_directory, proj_dir))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--test-directory", required=True)

    args = parser.parse_args()
    check_test_directory(args.test_directory)

    print("Successfully finished testing projects.")
