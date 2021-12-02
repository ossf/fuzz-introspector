# Copyright 2021 Ada Logics Ltd.
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
import signal
import argparse
import subprocess
import sys
import json
import threading
import shutil


def build_proj_with_default(project_name):
    try:
        subprocess.check_call("python3 infra/helper.py build_fuzzers %s"%(project_name), shell=True)
    except:
        print("Building default failed")
        exit(5)

def build_proj_with_coverage(project_name):
    try:
        subprocess.check_call("python3 infra/helper.py build_fuzzers --sanitizer=coverage %s"%(project_name), shell=True)
    except:
        print("Building with coverage failed")
        exit(5)

def get_fuzzers(project_name):
    execs = []
    for l in os.listdir("build/out/%s"%(project_name)):
        print("Checking %s"%(l))
        complete_path = os.path.join("build/out/%s"%(project_name), l)
        executable = (os.path.isfile(complete_path) and os.access(complete_path, os.X_OK))
        if executable:
            execs.append(l)
    print("Executable files: %s"%(str(execs)))
    return execs

def get_next_corpus_dir():
    max_idx = -1
    for f in os.listdir("."):
        if "corpus-" in f:
            try:
                idx = int(f[len("corpus-"):])
                if idx > max_idx: 
                    max_idx = idx
            except:
                None
    return "corpus-%d"%(max_idx+1)

def get_recent_corpus_dir():
    max_idx = -1
    for f in os.listdir("."):
        if "corpus-" in f:
            try:
                idx = int(f[len("corpus-"):])
                if idx > max_idx: 
                    max_idx = idx
            except:
                None
    return "corpus-%d"%(max_idx)

def run_all_fuzzers(project_name, fuzztime):
    # First get all fuzzers names
    fuzzer_names = get_fuzzers(project_name)

    corpus_dir = get_next_corpus_dir()
    os.mkdir(corpus_dir)
    for f in fuzzer_names:
        print("Running %s"%(f))
        target_corpus = "./%s/%s"%(corpus_dir, f)
        target_crashes = "./%s/%s"%(corpus_dir, "crashes_%s"%(f))
        os.mkdir(target_corpus)
        os.mkdir(target_crashes)

        cmd = ["python3 ./infra/helper.py run_fuzzer --corpus-dir=%s %s %s -max_total_time=%d -detect_leaks=0"%(target_corpus, project_name, f, fuzztime)]
        try:
            subprocess.check_call(" ".join(cmd), shell=True)
            print("Execution finished without exception")
        except:
            print("Executing finished with exception")

        # Now check if there are any crash files.
        for l in os.listdir("."):
            if "crash-" in l or "leak-" in l:
                shutil.move(l, target_crashes)

def get_coverage(project_name):
    #1 Find all coverage reports
    corpus_dir = get_recent_corpus_dir()

    #2 Copy them into the right folder
    for f in os.listdir(corpus_dir):
        if os.path.isdir("build/corpus/%s/%s"%(project_name, f)):
            shutil.rmtree("build/corpus/%s/%s"%(project_name, f))
        shutil.copytree(os.path.join(corpus_dir, f), "build/corpus/%s/%s"%(project_name, f))

    #3 run coverage command
    try:
        subprocess.check_call("python3 infra/helper.py coverage  --no-corpus-download %s"%(project_name), shell=True)#, timeout=60)
    except:
        print("Could not run coverage reports")


    #try:
    #    subprocess.check_call("docker kill $(docker ps -qa)", shell=True)
    #except:
    #    None

    print("Copying report")
    shutil.copytree("./build/out/%s/report"%(project_name), "./%s/report"%(corpus_dir))
    try:
        summary_file = "build/out/%s/report/linux/summary.json"%(project_name)
        with open(summary_file, "r") as fj:
            content = json.load(fj)
            for dd in content['data']:
                if "totals" in dd:
                    if "lines" in dd['totals']:
                        print("lines: %s"%(dd['totals']['lines']['percent']))
                        lines_percent = dd['totals']['lines']['percent']        
                        print("lines_percent: %s"%(lines_percent))
                        return lines_percent
    except:
        return None

    # Copy the report into the corpus directory
    print("Finished")


def complete_coverage_check(project_name, fuzztime):
    build_proj_with_default(project_name)
    run_all_fuzzers(project_name, fuzztime)
    build_proj_with_coverage(project_name)
    percent = get_coverage(project_name)
 
    return percent

def get_single_cov(project, target, corpus_dir):
    print("BUilding single project")
    build_proj_with_coverage(project)

    try:
        subprocess.check_call("python3 infra/helper.py coverage --no-corpus-download --fuzz-target %s --corpus-dir %s %s"%(target, corpus_dir, project_name), shell=True)#, timeout=60)
    except:
        print("Could not run coverage reports")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("usage: python3 ./get_full_coverage.py PROJECT_NAME FUZZTIME")
        exit(5)
    try:
        fuzztime = int(sys.argv[2])
    except:
        fuzztime = 40
    print("Using fuzztime %d"%(fuzztime))

    complete_coverage_check(sys.argv[1], fuzztime)
