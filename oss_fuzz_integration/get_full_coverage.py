# Copyright 2021 Fuzz Introspector Authors
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
        subprocess.check_call(
            "python3 infra/helper.py build_fuzzers --clean %s"%(project_name),
            shell=True
        )
    except:
        print("Building default failed")
        exit(5)


def build_proj_with_coverage(project_name):
    cmd = [
        "python3",
        "infra/helper.py",
        "build_fuzzers",
        "--sanitizer=coverage",
        project_name
    ]
    try:
        subprocess.check_call(
            " ".join(cmd),
            shell=True
        )
    except:
        print("Building with coverage failed")
        exit(5)


def get_fuzzers(project_name):
    execs = []
    for l in os.listdir("build/out/%s"%(project_name)):
        print("Checking %s"%(l))
        if l in {'llvm-symbolizer', 'sanitizer_with_fuzzer.so'}:
            continue
        if l.startswith('jazzer_'):
            continue
        complete_path = os.path.join("build/out/%s"%(project_name), l)
        executable = (os.path.isfile(complete_path) and os.access(complete_path, os.X_OK))
        if executable:
            execs.append(l)
    print("Fuzz targets: %s"%(str(execs)))
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


def run_all_fuzzers(project_name, fuzztime, job_count):
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

        cmd = [
            "python3",
            "./infra/helper.py",
            "run_fuzzer",
            "--corpus-dir=%s"%(target_corpus),
            "%s"%(project_name),
            "%s"%(f),
            "--",
            "-max_total_time=%d"%(fuzztime),
            "-detect_leaks=0"
        ]

        # If job count is non-standard, apply here
        if job_count != 1:
            # import psutil here to avoid having to install package
            # when not using this feature
            import psutil
            #Utilize half cores if max is indicated
            max_core_num = round(psutil.cpu_count()/2)
            if job_count == 0 or job_count > max_core_num:
                job_count = max_core_num

            print("Non-standard job count. Running: %d jobs"%(job_count))
            cmd.append("-workers=%d"%(job_count))
            cmd.append("-jobs=%d"%(job_count))


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
        shutil.copytree(
            os.path.join(corpus_dir, f),
            "build/corpus/%s/%s"%(project_name, f)
            )

    #3 run coverage command
    cmd = [
        "python3",
        "infra/helper.py",
        "coverage",
        "--port ''",
        "--no-corpus-download",
        project_name
    ]
    try:
        subprocess.check_call(
            " ".join(cmd),
            shell=True
        )
    except:
        print("Could not run coverage reports")


    print("Copying report")
    shutil.copytree(
        "./build/out/%s/report"%(project_name),
        "./%s/report"%(corpus_dir)
    )
    shutil.copytree(
        "./build/out/%s/report_target"%(project_name),
        "./%s/report_target"%(corpus_dir)
    )
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


def complete_coverage_check(project_name: str, fuzztime: int, job_count: int):
    build_proj_with_default(project_name)
    run_all_fuzzers(project_name, fuzztime, job_count)
    build_proj_with_coverage(project_name)
    percent = get_coverage(project_name)
 
    return percent


def get_single_cov(project, target, corpus_dir):
    print("BUilding single project")
    build_proj_with_coverage(project)

    cmd = [
        "python3",
        "infra/helper.py",
        "coverage",
        "--no-corpus-download",
        "--fuzz-target",
        target,
        "--corpus-dir",
        corpus_dir,
        project_name
    ]
    try:
        subprocess.check_call(" ".join(cmd))
    except:
        print("Could not run coverage reports")


def get_cmdline_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "project",
        metavar="P",
        help="Name of project to run"
    )
    parser.add_argument(
        "fuzztime",
        metavar="T",
        help="Number of seconds to run fuzzers for",
        type=int
    )
    parser.add_argument(
        "--jobs",
        type=int,
        help="Number of jobs to run in parallel. Zero indicates max count (half CPU cores)",
        default=1
    )
    return parser

if __name__ == "__main__":
    parser = get_cmdline_parser()
    args = parser.parse_args()

    print("Getting full coverage:")
    print("  project = %s"%(args.project))
    print("  fuzztime = %d"%(args.fuzztime))
    print("  jobs = %d"%(args.jobs))
    complete_coverage_check(args.project, args.fuzztime, args.jobs)
