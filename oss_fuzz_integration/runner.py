#!/usr/bin/env python3
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
import re
import sys
import signal
import argparse
import subprocess
import sys
import json
import threading
import shutil
import requests
import zipfile
from typing import Optional

THIS_DIR=os.path.dirname(os.path.abspath(__file__))

def download_public_corpus(
    project_name,
    fuzzer_name,
    target_zip
):
    OSS_FUZZ_PUBLIC_CORPUS = "https://storage.googleapis.com/%s-backup.clusterfuzz-external.appspot.com/corpus/libFuzzer/%s/public.zip"

    # There is a special case where the names of projects aren't added to links to public
    # corpora if the names of fuzz targets already start with their project's name + "_":
    # https://github.com/google/oss-fuzz/blob/7797279c274d10197d62841dc43834238fd483a1/infra/cifuzz/clusterfuzz_deployment.py#L295-L298
    if fuzzer_name.startswith(f"{project_name}_"):
        download_url = OSS_FUZZ_PUBLIC_CORPUS % (project_name, fuzzer_name)
    else:
        download_url = OSS_FUZZ_PUBLIC_CORPUS % (project_name, f"{project_name}_{fuzzer_name}")

    cmd = f"wget {download_url} -O {target_zip}"
    if subprocess.run(cmd, shell=True).returncode != 0:
        subprocess.run(f"rm -f {target_zip}", shell=True)
        return False

    return True


def download_full_public_corpus(project_name, target_corpus_dir: None):
    # First build the project which we use to identify fuzzers
    build_project(project_name, to_clean = True)

    if not target_corpus_dir:
        target_corpus_dir = f"{project_name}-corpus"

    if not os.path.isdir(target_corpus_dir):
        os.mkdir(target_corpus_dir)

    fuzzers = get_fuzzers(project_name)
    for fuzzer in fuzzers:
        if not download_public_corpus(project_name, fuzzer, f"corpus-{project_name}-{fuzzer}.zip"):
            print(f"Failed to download corpus for f{fuzzer}, ignoring")
            continue

        target_fuzzer_dir = os.path.join(target_corpus_dir, fuzzer)
        if not os.path.isdir(target_fuzzer_dir):
            os.mkdir(target_fuzzer_dir)

        target_zip = f"corpus-{project_name}-{fuzzer}.zip"
        subprocess.check_call(f"unzip {target_zip} -d {target_fuzzer_dir}/", shell=True)


def build_project(
    project_name,
    source_dir = None,
    sanitizer = None,
    to_clean = False
):
    """Wrapper for building projects using OSS-Fuzz's helper.py"""
    cmd = ["python3", "infra/helper.py", "build_fuzzers"]
    if sanitizer is not None:
        cmd.append("--sanitizer")
        cmd.append(sanitizer)
    if to_clean:
        cmd.append("--clean")
    cmd.append(project_name)
    if source_dir is not None:
        cmd.append(source_dir)

    try:
        subprocess.check_call(" ".join(cmd), shell=True)
    except:
        print("Building project failed")
        exit(1)


def patch_jvm_build(project_build_path):
    # Patch build.sh to include fuzz-introspector logic for JVM project
    if os.path.exists(project_build_path):
        content = ''
        with open(os.path.join(THIS_DIR, 'jvm.patch')) as file_handle:
            content = file_handle.read()
        with open(project_build_path, 'a+') as file_handle:
            file_handle.write('\n')
            file_handle.write(content)


def patch_jvm_source_report(server_directory):
    """
    Jacoco HTML report showing the source coverage does not have
    labels for each source code line. This patch aims to add labels
    to all non-statement lines to allow better pointer from the
    call tree to non-statement lines, including function signature.
    """
    # Search for all source code files in the base directory and patch them
    print("Patching html for JVM source html report")
    for root, _, files in os.walk(os.path.abspath(server_directory)):
        for file in files:
            if file.endswith(".java.html"):
                print(f"Patching {os.path.join(root, file)}")
                out_lines = []

                # Read file line by line
                with open(os.path.join(root, file), "r") as f:
                    lines = f.readlines()

                # Loop through each lines of the html and add labels
                # Last line is ignored
                for index in range(len(lines) - 1):
                    line = lines[index].replace("\n", "")
                    if index == 0:
                        # Special handle for first line
                        prefix = line[:line.rfind(">") + 1]
                        content = line[line.rfind(">") + 1:]
                        line = '%s<div id="L1" style="display: inline">%s</div>' % (prefix, content)
                    elif (not line.startswith('<span class="')):
                        # Handle line with no label
                        line = '<div id="L%d" style="display: inline">%s</div>' % (index + 1, line)
                    out_lines.append(line)

                # Write file line by line
                with open(os.path.join(root, file), "w+") as f:
                    f.write("\n".join(out_lines))
    print("Finish patching JVM source html report")


def patch_jvm_source_dead_link(server_directory, prefix):
    """
    Jacoco HTML report relies on the original project to provide the
    necessary source code file. If source code file for some libraries
    or dependencies are missing, they will not be possible to shown in
    source report format and those links will be dead. This patch aim
    to check all those link and disable them if the link is dead.
    """
    # Patch dead link in fuzz_report.html (stored in js files)
    print("Start patching dead link in fuzz_report.html")

    for root, _, files in os.walk(os.path.abspath(server_directory)):
        for file in files:
            if file.endswith(".js") or file.endswith("fuzz_report.html"):

                # Read js file
                with open(os.path.join(root, file)) as f:
                    report = f.read()

                # Replace dead link with '#'
                links = re.findall(r'href=[\'"]?([^\'" >]+)', report)
                links.extend(re.findall(r'[\'"]func_url[\'"]:\ [\'"]?([^\'" >]+)', report))
                for link in [link for link in links if link.startswith(prefix)]:
                    if not os.path.exists(os.path.join(server_directory, link[1:].split("#")[0])):
                        report = report.replace(link, "#")

                # Write result back to js file
                with open(os.path.join(root, file), "w+") as f:
                    f.write(report)

    print("Finish patching dead link in fuzz_Report.html")


def has_append(project_build_path):
    # Check if JVM build patch has been applied
    if os.path.exists(project_build_path):
        with open(project_build_path) as file_handle:
            content = file_handle.read()
            for line in content.splitlines():
                if 'export SET_FUZZINTRO_JVM="SET"' in line:
                    return True
    return False


def get_project_lang(project_name):
    # Check project.yaml for project langauge
    project_yaml_path = './projects/%s/project.yaml' % project_name
    if os.path.exists(project_yaml_path):
        with open(project_yaml_path) as file_handle:
            content = file_handle.read()
            for line in content.splitlines():
                match = re.compile(r'\s*language\s*:\s*([^\s]+)').match(line)
                if match:
                    return match.group(1)

    # Cannot locate project language, return default value
    return 'c++'


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
            continue

        # For jvm, os.X_OK won't be true. Instead, we do another heuristic,
        # which is checking for the precense of a .class file for a fuzzer
        # and whether LLVMFuzzerTestOneInput is in a given potential wrapper
        # script.
        potential_class_file = complete_path + ".class"
        if os.path.isfile(potential_class_file):
            # Check if "LLVMFuzzerTestOneInput" is in the original
            with open(complete_path, 'r') as fuzzer_script:
                content = fuzzer_script.read()
                if "LLVMFuzzerTestOneInput" in content:
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


def run_all_fuzzers(project_name, fuzztime, job_count, corpus_dir):
    # First get all fuzzers names
    fuzzer_names = get_fuzzers(project_name)

    user_provided_corpus = corpus_dir is not None

    if corpus_dir is None:
        corpus_dir = get_next_corpus_dir()
    if not os.path.isdir(corpus_dir):
        os.mkdir(corpus_dir)

    for f in fuzzer_names:
        print("Running fuzzer %s"%(f))
        target_corpus = "./%s/%s"%(corpus_dir, f)
        target_crashes = "./%s/%s"%(corpus_dir, "crashes_%s"%(f))
        if not os.path.isdir(target_corpus):
            os.mkdir(target_corpus)
        if not os.path.isdir(target_crashes):
            os.mkdir(target_crashes)

        cmd = [
            "python3",
            "./infra/helper.py",
            "run_fuzzer",
            "--corpus-dir=%s"%(target_corpus),
        ]
        # We must set this to avoid triggering
        # https://github.com/google/oss-fuzz/blob/05b2e6dd5e3c08a5d11fa7a46f3ed8f555ff9a7f/infra/base-images/base-runner/run_fuzzer#L29-L36
        if user_provided_corpus:
            cmd.append(f"-e=\"CORPUS_DIR=/tmp/{f}_corpus\"")
        cmd += [
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


        print("Running fuzzing command: %s"%(" ".join(cmd)))
        try:
            subprocess.check_call(" ".join(cmd), shell=True)
            print("Execution finished without exception")
        except:
            print("Executing finished with exception")

        # Now check if there are any crash files.
        for l in os.listdir("."):
            if "crash-" in l or "leak-" in l:
                shutil.move(l, target_crashes)


def get_coverage(project_name, corpus_dir):
    #1 Find all coverage reports
    if corpus_dir is None:
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
    # Delete the existing coverage report
    if os.path.isdir("./%s/report"%(corpus_dir)):
        shutil.rmtree("./%s/report"%(corpus_dir))
    if os.path.isdir("./%s/report_target"%(corpus_dir)):
        shutil.rmtree("./%s/report_target"%(corpus_dir))

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


def setup_next_corpus_dir(project_name):
    fuzzer_names = get_fuzzers(project_name)
    corpus_dir = get_next_corpus_dir()
    if not os.path.isdir(corpus_dir):
        os.mkdir(corpus_dir)

    return corpus_dir


def complete_coverage_check(
    project_name: str,
    source_dir: Optional[str],
    fuzztime: int,
    job_count: int,
    corpus_dir: Optional[str],
    download_public_corpus: bool
):
    # Check if it is JVM Project
    if get_project_lang(project_name) == 'jvm':
        project_build_path = './projects/%s/build.sh' % project_name
        # Check if fuzz-introspector patch already appended
        if not has_append(project_build_path):
            # Apply jvm build patch to include fuzz-introspector logic
            #patch_jvm_build(project_build_path)
            print("tmp")

    build_project(project_name, source_dir, to_clean=True)

    if download_public_corpus:
        corpus_dir = setup_next_corpus_dir(project_name)
        download_full_public_corpus(project_name, corpus_dir)

    run_all_fuzzers(project_name, fuzztime, job_count, corpus_dir)
    build_project(project_name, source_dir, sanitizer="coverage")
    percent = get_coverage(project_name, corpus_dir)

    return percent


def introspector_run(
    project_name: str,
    source_dir: Optional[str],
    fuzztime: int,
    job_count: int,
    corpus_dir: Optional[str],
    port: int,
    download_public_corpus: bool,
    collect_coverage: bool
):
    if collect_coverage:
        complete_coverage_check(
            project_name,
            source_dir,
            fuzztime,
            job_count,
            corpus_dir,
            download_public_corpus
        )
    else:
        build_project(project_name, source_dir, to_clean=True)
        setup_next_corpus_dir(project_name)

    curr_dir = os.path.abspath(".")

    # Build sanitizers with introspector
    build_project(project_name, source_dir, sanitizer="introspector")

    # get the latest corpus
    latest_corpus_dir = get_recent_corpus_dir()

    # copy over inpsoector and coverage reports

    # copy over reports:
    # - introspector
    # - project coverage
    # - per-fuzzer coverage
    if os.path.isdir(os.path.join(latest_corpus_dir, "inspector-report")):
        shutil.rmtree(os.path.join(latest_corpus_dir, "inspector-report"))

    shutil.copytree(
        os.path.join(curr_dir, "build", "out", project_name, "inspector"),
        os.path.join(latest_corpus_dir, "inspector-report")
    )
    if collect_coverage:
        shutil.copytree(
            os.path.join(latest_corpus_dir, "report"),
            os.path.join(latest_corpus_dir, "inspector-report", "covreport")
        )

        for target_coverage_dir in os.listdir(os.path.join(latest_corpus_dir, "report_target")):
            shutil.copytree(
                os.path.join(latest_corpus_dir, "report_target", target_coverage_dir),
                os.path.join(latest_corpus_dir, "inspector-report", "covreport", target_coverage_dir)
            )
    server_directory = os.path.join(latest_corpus_dir, "inspector-report")

    # Patch all jacoco source html report for JVM project
    if get_project_lang(project_name) == 'jvm':
        patch_jvm_source_report(server_directory)
        patch_jvm_source_dead_link(server_directory, "/covreport")

    # start webserver
    cmd = "python3 -m http.server %d --directory %s" % (port, server_directory)
    print("The following command is about to be run to start a webserver: %s"%(cmd))
    subprocess.check_call(cmd, shell=True)


def get_single_cov(project, target, corpus_dir):
    print("Building single project")
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

    subparsers = parser.add_subparsers(dest="command")

    coverage_parser = subparsers.add_parser("coverage")
    coverage_parser.add_argument(
        "project",
        metavar="P",
        help="Name of project to run"
    )
    coverage_parser.add_argument(
        "fuzztime",
        metavar="T",
        help="Number of seconds to run fuzzers for",
        type=int
    )
    coverage_parser.add_argument(
        "--jobs",
        type=int,
        help="Number of jobs to run in parallel. Zero indicates max count (half CPU cores)",
        default=1
    )
    coverage_parser.add_argument(
        "--corpus-dir",
        type=str,
        help="directory with corpus for the project",
        default=None
    )
    coverage_parser.add_argument(
        "--download-public-corpus",
        action="store_true",
        help="if set, will download public corpus",
        default=False
    )
    coverage_parser.add_argument(
        "--source-dir",
        type=str,
        help="path to source",
        default=None
    )

    introspector_parser = subparsers.add_parser("introspector")
    introspector_parser.add_argument(
        "project",
        metavar="P",
        help="Name of project to run"
    )
    introspector_parser.add_argument(
        "fuzztime",
        metavar="T",
        help="Number of seconds to run fuzzers for",
        type=int
    )
    introspector_parser.add_argument(
        "--jobs",
        type=int,
        help="Number of jobs to run in parallel. Zero indicates max count (half CPU cores)",
        default=1
    )
    introspector_parser.add_argument(
        "--corpus-dir",
        type=str,
        help="directory with corpus for the project",
        default=None
    )
    introspector_parser.add_argument(
        "--port",
        type=int,
        default=8008
    )
    introspector_parser.add_argument(
        "--download-public-corpus",
        action="store_true",
        help="if set, will download public corpus",
        default=False
    )
    introspector_parser.add_argument(
        "--no-coverage",
        action="store_true",
        help="Do not run coverage in this case",
        default=False
    )
    introspector_parser.add_argument(
        "--source-dir",
        type=str,
        help="path to source",
        default=None
    )

    download_corpus_parser = subparsers.add_parser("download-corpus")
    download_corpus_parser.add_argument(
        "project",
        help="name of project"
    )
    download_corpus_parser.add_argument(
        "--corpus-dir",
        type=str,
        help="directory with corpus for the project",
        default=None
    )
    return parser

if __name__ == "__main__":
    parser = get_cmdline_parser()
    args = parser.parse_args()

    if args.command == "coverage":
        print("Getting full coverage:")
        print("  project = %s"%(args.project))
        print("  fuzztime = %d"%(args.fuzztime))
        print("  jobs = %d"%(args.jobs))
        complete_coverage_check(
            args.project,
            args.source_dir,
            args.fuzztime,
            args.jobs,
            args.corpus_dir,
            args.download_public_corpus
        )
    elif args.command == "introspector":
        print("Running full")
        introspector_run(
            args.project,
            args.source_dir,
            args.fuzztime,
            args.jobs,
            args.corpus_dir,
            args.port,
            args.download_public_corpus,
            not args.no_coverage
        )
    elif args.command == "download-corpus":
        download_full_public_corpus(args.project, args.corpus_dir)
