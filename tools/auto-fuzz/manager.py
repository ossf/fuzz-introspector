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

import os
import sys
import yaml
import json
import shutil
import subprocess
import constants
import shlex
import threading
try:
    import tqdm
except ImportError:
    print("No tqdm module, skipping progress bar")

# Auto-fuzz modules
import base_files
import oss_fuzz_manager
import fuzz_driver_generation_python

from typing import List, Any
from multiprocessing.dummy import Pool as ThreadPool

# Set default directories and error if they do not exist
basedir = os.path.dirname(os.path.realpath(__file__))
FUZZ_INTRO_BASE = basedir + "/../../"
OSS_FUZZ_BASE = basedir + "/../../../oss-fuzz"
FUZZ_INTRO_PYTHON_MAIN = os.path.join(FUZZ_INTRO_BASE, "frontends", "python",
                                      "main.py")

if not os.path.isdir(FUZZ_INTRO_BASE):
    raise Exception("Could not find fuzz introspector directory")

if not os.path.isfile(FUZZ_INTRO_PYTHON_MAIN):
    raise Exception("Could not find fuzz introspector runner")

if not os.path.isdir(OSS_FUZZ_BASE):
    raise Exception("Could not find OSS-Fuzz directory")


class OSS_FUZZ_PROJECT:
    """Abstraction of OSS-Fuzz project.

    Provides helper methods for easily managing files and folders and
    operations on a given OSS-Fuzz project.
    """

    def __init__(self, project_folder, github_url):
        self.project_folder = project_folder
        self.github_url = github_url

    @property
    def build_script(self):
        return self.project_folder + "/build.sh"

    @property
    def dockerfile(self):
        return self.project_folder + "/Dockerfile"

    @property
    def project_yaml(self):
        return self.project_folder + "/project.yaml"

    @property
    def base_fuzzer(self):
        return self.project_folder + "/fuzz_1.py"

    @property
    def oss_fuzz_project_name(self):
        return os.path.basename(self.project_folder)

    @property
    def oss_fuzz_fuzzer_namer(self):
        return os.path.basename(self.base_fuzzer).replace(".py", "")

    @property
    def project_name(self):
        # Simplify url by cutting https out, then assume what we have left is:
        # github.com/{user}/{proj_name}
        return self.github_url.replace("https://", "").split("/")[2]

    def write_basefiles(self):
        with open(self.build_script, "w") as bfile:
            bfile.write(base_files.gen_builder_1())

        with open(self.base_fuzzer, "w") as ffile:
            ffile.write(base_files.gen_base_fuzzer())

        with open(self.project_yaml, "w") as yfile:
            yfile.write(base_files.gen_project_yaml(self.github_url))

        with open(self.dockerfile, "w") as dfile:
            dfile.write(
                base_files.gen_dockerfile(self.github_url, self.project_name))


def get_next_project_folder(base_dir):
    AUTOFUZZDIR = "autofuzz-"
    max_idx = -1
    for dirname in os.listdir(base_dir):
        try:
            idx = int(dirname.replace("autofuzz-", ""))
            if idx > max_idx:
                max_idx = idx
        except:
            pass
    return os.path.join(base_dir, AUTOFUZZDIR + str(max_idx + 1))


def run_cmd(cmd, timeout_sec):
    #print("Running command %s" % (cmd))
    proc = subprocess.Popen(shlex.split(cmd),
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    timer = threading.Timer(timeout_sec, proc.kill)
    try:
        timer.start()
        stdout, stderr = proc.communicate()
        #print(stdout)
        #print("---------")
        #print(stderr)
    finally:
        no_timeout = timer.is_alive()
        timer.cancel()
    return no_timeout


def run_static_analysis(git_repo, basedir):
    possible_imports = set()
    curr_dir = os.getcwd()
    os.chdir(basedir)
    os.mkdir("work")
    os.chdir("work")

    cmd = ["git clone --depth=1", git_repo]
    try:
        subprocess.check_call(" ".join(cmd),
                              shell=True,
                              timeout=180,
                              stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        pass

    cmd = [
        "python3", FUZZ_INTRO_PYTHON_MAIN, "--fuzzer", "../fuzz_1.py",
        "--package=%s" % (os.getcwd())
    ]
    ret = run_cmd(" ".join(cmd), 1800)
    if not os.path.isfile("fuzzerLogFile-fuzz_1.data.yaml"):
        ret = False
    ret = True

    os.chdir(curr_dir)
    return ret


def copy_core_oss_fuzz_project_files(src_oss_project, dst_oss_project):
    shutil.copy(src_oss_project.build_script, dst_oss_project.build_script)
    shutil.copy(src_oss_project.project_yaml, dst_oss_project.project_yaml)
    shutil.copy(src_oss_project.dockerfile, dst_oss_project.dockerfile)


def copy_oss_fuzz_project_source(src_oss_project, dst_oss_project):
    shutil.copytree(
        os.path.join(src_oss_project.project_folder,
                     src_oss_project.project_name),
        os.path.join(dst_oss_project.project_folder,
                     dst_oss_project.project_name))


tqdm_tracker = None


def tick_tqdm_tracker():
    global tqdm_tracker
    try:
        tqdm_tracker.update(1)
    except:
        return


def build_and_test_single_possible_target(idx_folder,
                                          idx,
                                          oss_fuzz_base_project,
                                          possible_targets,
                                          should_run_checks=True):
    """Builds and tests a given FuzzTarget.

    1) copies the base oss-fuzz project into the target idx autofuzz dir
    2) patches the fuzzer in the new autofuzz dir
    3) builds the autofuzz dir as an oss-fuzz project
    4) runs the oss-fuzz project in the event of a successful build
    5) cleans up the oss-fuzz project artifacts
    """
    auto_fuzz_proj_dir = idx_folder + str(idx)
    os.mkdir(auto_fuzz_proj_dir)

    # Create the new OSS-Fuzz project for the FuzzTarget to validate
    dst_oss_fuzz_project = OSS_FUZZ_PROJECT(auto_fuzz_proj_dir,
                                            oss_fuzz_base_project.github_url)

    # Copy files from base OSS-Fuzz project
    copy_core_oss_fuzz_project_files(oss_fuzz_base_project,
                                     dst_oss_fuzz_project)
    copy_oss_fuzz_project_source(oss_fuzz_base_project, dst_oss_fuzz_project)

    # Log dir
    idx_logdir = os.path.join(auto_fuzz_proj_dir, "autofuzz-log")
    os.mkdir(idx_logdir)

    # Patch the fuzzer in the auto-fuzz directory according to the target
    # we want to validate.
    possible_target = possible_targets[idx]
    fuzzer_source = possible_target.generate_patched_fuzzer(
        oss_fuzz_base_project.base_fuzzer)
    with open(dst_oss_fuzz_project.base_fuzzer, "w") as fl:
        fl.write(fuzzer_source)

    if not should_run_checks:
        tick_tqdm_tracker()
        return

    # Run OSS-Fuzz checks; first build then running fuzzers
    build_success = oss_fuzz_manager.copy_and_build_project(auto_fuzz_proj_dir,
                                                            OSS_FUZZ_BASE,
                                                            log_dir=idx_logdir)
    oss_fuzz_manager.check_if_proj_runs(
        OSS_FUZZ_BASE, dst_oss_fuzz_project.oss_fuzz_project_name,
        dst_oss_fuzz_project.oss_fuzz_fuzzer_namer, idx_logdir)

    # Check if OSS-Fuzz build was successful.
    run_success = False
    with open(os.path.join(idx_logdir, "oss-fuzz-run.out"), "r") as ofrun_f:
        run_log = ofrun_f.read()
        if "Traceback" not in run_log:
            run_success = True

    #print("%s - build [%s] - run [%s]" %
    #      (os.path.basename(auto_fuzz_proj_dir), str(build_success),
    #       str(run_success)))

    # Log results.
    summary = dict()
    summary['auto-build'] = str(build_success)
    summary['auto-run'] = str(run_success)
    summary['target function'] = possible_target.function_target
    summary['heuristics-used'] = list()
    for heuristic in possible_target.heuristics_used:
        summary['heuristics-used'].append(heuristic)
    with open(os.path.join(auto_fuzz_proj_dir, "result.json"),
              "w") as summary_file:
        json.dump(summary, summary_file)

    # Cleanup oss-fuzz artifacts
    oss_fuzz_manager.cleanup_project(os.path.basename(auto_fuzz_proj_dir),
                                     OSS_FUZZ_BASE)

    # Cleanup source code folders in auto fuzz dir and in oss-fuzz dir.
    for src_dir in os.listdir(auto_fuzz_proj_dir):
        full_path = os.path.join(auto_fuzz_proj_dir, src_dir)
        if not os.path.isdir(full_path):
            continue

        if dst_oss_fuzz_project.project_name not in src_dir:
            continue

        # Clean drectory in auto-fuzz dir
        shutil.rmtree(full_path)

        # Clean up the directory in oss-fuzz
        oss_fuzz_path = os.path.join(OSS_FUZZ_BASE, "projects",
                                     os.path.basename(auto_fuzz_proj_dir),
                                     src_dir)
        shutil.rmtree(oss_fuzz_path)
    tick_tqdm_tracker()


def run_builder_pool(autofuzz_base_workdir, oss_fuzz_base_project,
                     possible_targets, max_targets_to_analyse):
    """Runs a set of possible oss-fuzz targets in `possible_targets` in a
    multithreaded manner using ThreadPools.
    """
    global tqdm_tracker

    # Create copies of all of our targets, start with empty too.
    idx_folder = os.path.join(
        autofuzz_base_workdir,
        os.path.basename(autofuzz_base_workdir) + "-idx-")
    arg_list = []
    for idx in range(len(possible_targets)):
        if idx > max_targets_to_analyse:
            continue
        arg_list.append(
            (idx_folder, idx, oss_fuzz_base_project, possible_targets))

    pool = ThreadPool(constants.MAX_THREADS)
    print("Launching multi-threaded processing")
    print("Jobs completed:")
    try:
        # Allow failing here in the event tqdm is not present
        tqdm_tracker = tqdm.tqdm(
            total=min(max_targets_to_analyse, len(possible_targets)))
    except:
        pass
    pool.starmap(build_and_test_single_possible_target, arg_list)
    pool.close()
    pool.join()
    try:
        tqdm_tracker.close()
    except:
        pass


def git_clone_project(github_url, destination):
    cmd = ["git clone --depth=1", github_url, destination]
    try:
        subprocess.check_call(" ".join(cmd),
                              shell=True,
                              timeout=180,
                              stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        return False
    except subprocess.CalledProcessError:
        return False
    return True


def autofuzz_project_from_github(github_url, do_static_analysis=False):
    """Auto-generates fuzzers for a Github project and performs runtime checks
    on the fuzzers.
    """
    print("Running autofuzz on %s" % (github_url))
    autofuzz_base_workdir = get_next_project_folder(base_dir=os.getcwd())
    os.mkdir(autofuzz_base_workdir)

    #autofuzz_data_dir = os.path.join(autofuzz_base_workdir, "base-autofuzz")
    base_oss_fuzz_project_dir = os.path.join(autofuzz_base_workdir,
                                             "base-autofuzz")
    os.mkdir(base_oss_fuzz_project_dir)

    # Create a OSS-Fuzz project abstraction for the base project.
    # A lot of derivatives will be created based off of this base project.
    oss_fuzz_base_project = OSS_FUZZ_PROJECT(base_oss_fuzz_project_dir,
                                             github_url)

    # Clone the target and store it in our base OSS-Fuzz project. We need to get
    # the source for both static analysis and also for running each OSS-Fuzz
    # experiment. We store it like this to avoid having "git clone" in each
    # experiment, but rather using Docker's COPY.
    if not git_clone_project(
            github_url,
            os.path.join(oss_fuzz_base_project.project_folder,
                         oss_fuzz_base_project.project_name)):
        return False

    # Generate the base Dockerfile, build.sh, project.yaml and fuzz_1.py
    oss_fuzz_base_project.write_basefiles()

    if do_static_analysis:
        print("Running static analysis on %s" % (github_url))
        static_res = run_static_analysis(github_url,
                                         oss_fuzz_base_project.project_folder)

    # Check basic fuzzer
    res = oss_fuzz_manager.copy_and_build_project(
        oss_fuzz_base_project.project_folder,
        OSS_FUZZ_BASE,
        log_dir=base_oss_fuzz_project_dir)

    # Generate all possible targets
    possible_targets = []
    if do_static_analysis and static_res:
        print("Generating fuzzers for %s" % (github_url))
        possible_targets = fuzz_driver_generation_python.generate_possible_targets(
            oss_fuzz_base_project.project_folder)
    print("Generated %d possible targets for %s." %
          (len(possible_targets), github_url))

    # Run all of the builders
    print("Running runtime checking on %d fuzzers for %s" % (min(
        constants.MAX_FUZZERS_PER_PROJECT, len(possible_targets)), github_url))
    run_builder_pool(autofuzz_base_workdir, oss_fuzz_base_project,
                     possible_targets, constants.MAX_FUZZERS_PER_PROJECT)
    return True


def run_on_projects(repos_to_target=constants.python_git_repos):
    """Run autofuzz generation on a list of Github projects."""
    home_dir = os.getcwd()
    for repo in repos_to_target:
        os.chdir(home_dir)
        autofuzz_project_from_github(repo, do_static_analysis=True)

    print("Completed auto-fuzz generation on %d projects" %
          len(repos_to_target))


if __name__ == "__main__":
    run_on_projects()
