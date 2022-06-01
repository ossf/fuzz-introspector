#!/usr/bin/python3
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
"""Module for testing OSS-Fuzz projects"""

import os
import sys
import shutil
import subprocess

import project_checker

SCRIPT_DIR = os.path.realpath(os.path.dirname(os.path.realpath(__file__)))

OSS_FUZZ_HELPER = os.path.realpath(os.getcwd()) + "/infra/helper.py"
COV_HELPER      = SCRIPT_DIR + "/get_full_coverage.py"
PROJ_CHECK      = SCRIPT_DIR + "/project-checker.py"

# find next test dir
def get_latest_dir(dirname):
    curr_index = -1
    for l in os.listdir(os.getcwd()):
        if dirname in l:
            curr_index = max(int(l.replace(dirname, "")), curr_index)
    return curr_index


def run_full_cov(project):
    cmd = []
    cmd.append("python3")
    cmd.append(COV_HELPER)
    cmd.append(project)
    cmd.append("10") # seconds to run

    covlog = open("get_coverage.log", "wb")
    subprocess.check_call(
        " ".join(cmd),
        stdout=covlog,
        stderr=covlog,
        shell=True
    )


def run_fuzz_introspector(project):
    cmd = []
    cmd.append("python3")
    cmd.append(OSS_FUZZ_HELPER)
    cmd.append("build_fuzzers")
    cmd.append("--sanitizer=introspector")
    cmd.append(project)

    build_log = open("build_introspector.log", "wb")
    try:
        subprocess.check_call(
            " ".join(cmd),
            stdout = build_log,
            stderr = build_log,
            shell=True
        )
    except:
        return False
    return True


def main_loop():
    testdir = "test-report-" + str((get_latest_dir("test-report-") + 1))
    print("Test directory: %s"%(testdir))
    os.mkdir(testdir)

    projects_to_test = [
        "leveldb",
        "htslib",
        "jsoncpp",
        "unrar",
        "tarantool",
        "fio",
        "wuffs"
    ]

    build_results = []
    project_check_results = []
    for project in projects_to_test:
        print("Testing %s"%(project))

        # Building and running
        run_full_cov(project)
        latest_corp = "corpus-" + str(get_latest_dir("corpus-"))

        shutil.move("get_coverage.log", latest_corp + "/get_coverage.log")
        with open(os.path.join(latest_corp, "project_name"), "w") as pn:
            pn.write(project+"\n")
            
        fuzz_intro_success = run_fuzz_introspector(project)
        build_results.append((project, fuzz_intro_success))
        shutil.move(
            "build_introspector.log",
            latest_corp + "/build_introspector.log"
        )

        if fuzz_intro_success:
            # Copy fuzz-introspector related files over
            shutil.copytree(
                "build/out/%s/inspector/"%(project),
                os.path.join(latest_corp, "inspector-report")
            )
            shutil.copytree(
                os.path.join(latest_corp, "report"),
                os.path.join(latest_corp, "inspector-report/covreport")
            )

            for d in os.listdir(os.path.join(latest_corp, "report_target")):
                full_path = os.path.join(latest_corp, "report_target", d)
                shutil.copytree(
                    full_path,
                    os.path.join(latest_corp, "inspector-report/covreport/", d)
                )

        # Copy the entire corpus-X directory into the test directory
        target_dir = os.path.join(testdir, latest_corp)
        shutil.copytree(latest_corp, target_dir)

        # Check project checker
        try:
            project_checker.check_project_dir(target_dir)
            project_check_results.append((project, True, ""))
        except project_checker.ProjectCheckError as e:
            project_check_results.append((project, False, str(e)))


    print("Summary of building with fuzz-introspector:")
    for p, s in build_results:
        print("\t%s: %s"%(p, "success" if s else "failed"))

    print("Summary of data checker:")
    for p, s, m in project_check_results:
        print("\t%s: %s %s"%(p, "success" if s else "failed", m))


if __name__ == "__main__":
    main_loop()
