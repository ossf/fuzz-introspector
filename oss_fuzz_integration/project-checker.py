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

def err_exit(msg):
    print(f"Error {msg}")
    exit(0)

def guide_exit(msg):
    msg += (
        "\n Check the data and determine if there is a bug in fuzz-introspecto "
        "or the project changed. Please fix test data or fuzz-introspector accordingly."
    )
    err_exit(msg)

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
    if summary_dict['hts_open_fuzzer']['stats']['total-basic-blocks'] < 25000:
        guide_exit("htslib basic block count seems off.")
    if (summary_dict['MergedProjectProfile']['stats']['unreached-complexity-percentage'] < 30.0 or
        summary_dict['MergedProjectProfile']['stats']['unreached-complexity-percentage'] > 40.0):
        guide_exit("htslib unreached complexity percentage seems off.")
    if (summary_dict['hts_open_fuzzer']['coverage-blocker-stats']['cov-reach-proportion'] < 10.0 or
        summary_dict['hts_open_fuzzer']['coverage-blocker-stats']['cov-reach-proportion'] > 20.0):
        guide_exit("coverage reach proportion seems off.")

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
    if summary_dict['jsoncpp_fuzzer']['coverage-blocker-stats']['cov-reach-proportion'] < 50.0:
        guide_exit("coverage reach proportion seems off.")
    if summary_dict['jsoncpp_proto_fuzzer']['coverage-blocker-stats']['cov-reach-proportion'] < 50.0:
        guide_exit("coverage reach proportion seems off.")

    # Success
    return


def check_project_unrar(summary_dict):
    """Checks summary dict against htslib details"""
    fuzzer_list = []
    for k in summary_dict:
        if k != "MergedProjectProfile":
            fuzzer_list.append(k)
    if len(fuzzer_list) != 1:
        guide_exit("unrar fuzzer count is wrong")
    if summary_dict['unrar_fuzzer']['coverage-blocker-stats']['cov-reach-proportion'] < 10.0:
        guide_exit("coverage reach proportion seems off.")
    if summary_dict['unrar_fuzzer']['coverage-blocker-stats']['cov-reach-proportion'] > 80.0:
        guide_exit("coverage reach proportion seems off.")
    if summary_dict['unrar_fuzzer']['stats']['file-target-count'] < 40:
        guide_exit("file target count seems off.")

    # Success
    return

def check_specific_project(proj_name, build_log_file,coverage_log,summary_json):
    print(f"Checking {proj_name}")
    name_to_check_mapping = {
        "htslib":  check_project_htslib,
        "jsoncpp": check_project_jsoncpp,
        "unrar":   check_project_unrar
    }

    if proj_name not in name_to_check_mapping:
        print("Project cannot be checked. Moving on the next")
        return

    data = json.load(open(summary_json))
    name_to_check_mapping[proj_name](data)
    print("Check done")


def check_project_dir(proj_dir):
    print(f"Checking {proj_dir}")
    build_log_file   = os.path.join(proj_dir, "build_introspector.log")
    coverage_log     = os.path.join(proj_dir, "get_coverage.log")
    summary_json     = os.path.join(proj_dir, "inspector-report", "summary.json")
    proj_name_file   = os.path.join(proj_dir, "project_name")

    if not os.path.isfile(build_log_file):
        err_exit("No log file")
    if not os.path.isfile(coverage_log):
        err_exit("No coverage log")
    if not os.path.isfile(summary_json):
        err_exit("No summary file")
    print(proj_name_file)
    if not os.path.isfile(proj_name_file):
        err_exit("No project name file")

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
