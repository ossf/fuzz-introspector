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
import copy
import stat
import yaml
import json
import shutil
import subprocess
import constants
import requests
import shlex
import argparse
import tarfile
import threading
try:
    import tqdm
except ImportError:
    print("No tqdm module, skipping progress bar")

# temporary fix: adding fuzz-introspector to the system path
sys.path.insert(0, '../../src/')
from fuzz_introspector import commands

# Auto-fuzz modules
import oss_fuzz_manager
import post_process
import utils
from fuzzer_generator import fuzz_driver_generation_python
from fuzzer_generator import fuzz_driver_generation_java
from templates import base_files
from objects.oss_fuzz_project import OSS_FUZZ_PROJECT

from io import BytesIO
from typing import List, Any
from multiprocessing.dummy import Pool as ThreadPool

# Set default directories and error if they do not exist
tqdm_tracker = None
basedir = os.path.dirname(os.path.realpath(__file__))
FUZZ_INTRO_BASE = basedir + "/../../"
OSS_FUZZ_BASE = basedir + "/../../../oss-fuzz"
FUZZ_INTRO_MAIN = {
    "python": os.path.join(FUZZ_INTRO_BASE, "frontends", "python", "main.py"),
    "java": os.path.join(FUZZ_INTRO_BASE, "frontends", "java", "run.sh")
}

if not os.path.isdir(FUZZ_INTRO_BASE):
    raise Exception("Could not find fuzz introspector directory")

if not os.path.isfile(FUZZ_INTRO_MAIN["python"]):
    raise Exception("Could not find fuzz introspector runner for python")

if not os.path.isfile(FUZZ_INTRO_MAIN["java"]):
    raise Exception("Could not find fuzz introspector runner for java")

if not os.path.isdir(OSS_FUZZ_BASE):
    raise Exception("Could not find OSS-Fuzz directory")


def build_project(oss_fuzz_base_project, base_oss_fuzz_project_dir,
                  project_build_type):
    basedir = oss_fuzz_base_project.project_folder
    language = oss_fuzz_base_project.language
    build_ret = False
    jdk_key = None
    if basedir:
        if language == "java":
            # Loop and use each JDK version in order in the previous failed.
            # Order JDK15 (oss-fuzz default) -> JDK17 -> JDK11 -> JDK8
            for jdk in constants.JDK_HOME:
                jdk_dir = constants.JDK_HOME[jdk]

                oss_fuzz_base_project.change_dockerfile(
                    jdk, project_build_type)
                oss_fuzz_base_project.change_build_script(project_build_type)

                build_ret = oss_fuzz_manager.copy_and_build_project(
                    basedir, OSS_FUZZ_BASE, log_dir=base_oss_fuzz_project_dir)

                # Check if the build success with the current JDK version
                # and record that for future process and oss-fuzz test
                if build_ret:
                    jdk_key = jdk
                    break
                else:
                    # Clean static analysis oss-fuzz directory
                    folder = oss_fuzz_base_project.project_folder
                    oss_fuzz_manager.cleanup_project(os.path.basename(folder),
                                                     OSS_FUZZ_BASE)
        elif language == "python":
            build_ret = oss_fuzz_manager.copy_and_build_project(
                basedir, OSS_FUZZ_BASE, log_dir=base_oss_fuzz_project_dir)
        else:
            return (False, None)

    return (build_ret, jdk_key)


def run_static_analysis(oss_fuzz_base_project, base_oss_fuzz_project_dir):

    # Get project_dir
    project_dir = os.path.join(oss_fuzz_base_project.project_folder,
                               oss_fuzz_base_project.project_name)

    language = oss_fuzz_base_project.language

    project_build_type = utils.write_base_file(oss_fuzz_base_project,
                                               project_dir, language)
    if not project_build_type:
        print("Fail to generate base files\n")
        return False, None, None

    basedir = oss_fuzz_base_project.project_folder
    project_name = oss_fuzz_base_project.project_name

    build_ret, jdk_key = build_project(oss_fuzz_base_project,
                                       base_oss_fuzz_project_dir,
                                       project_build_type)

    if jdk_key:
        jdk_base = constants.JDK_HOME[jdk_key]
    else:
        jdk_base = None

    if not build_ret:
        print("Project build fail or static analysis fail.\n")
        return False, None, None

    static_ret = utils.check_and_copy_static_analysis_file(
        OSS_FUZZ_BASE, basedir, language)

    if not static_ret:
        print("Static analysis fail.\n")
        return False, None, None

    copy_ret = utils.copy_build_file(OSS_FUZZ_BASE, basedir, language)

    if not static_ret:
        print("Project build file copy fail.\n")
        return False, None, None

    return build_ret, jdk_base, project_build_type


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
                                          language,
                                          benchmark,
                                          project_build_type,
                                          jdk,
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
                                            oss_fuzz_base_project.github_url,
                                            language, benchmark)

    # Copy files from base OSS-Fuzz project
    utils.copy_core_oss_fuzz_project_files(oss_fuzz_base_project,
                                           dst_oss_fuzz_project)
    if language == "java":
        ant_path = os.path.join(oss_fuzz_base_project.project_folder,
                                "ant.zip")
        ant_dst = os.path.join(dst_oss_fuzz_project.project_folder, "ant.zip")
        maven_path = os.path.join(oss_fuzz_base_project.project_folder,
                                  "maven.zip")
        maven_dst = os.path.join(dst_oss_fuzz_project.project_folder,
                                 "maven.zip")
        gradle_path = os.path.join(oss_fuzz_base_project.project_folder,
                                   "gradle.zip")
        gradle_dst = os.path.join(dst_oss_fuzz_project.project_folder,
                                  "gradle.zip")
        protoc_path = os.path.join(oss_fuzz_base_project.project_folder,
                                   "protoc.zip")
        protoc_dst = os.path.join(dst_oss_fuzz_project.project_folder,
                                  "protoc.zip")
        build_jar_path = os.path.join(oss_fuzz_base_project.project_folder,
                                      "build-jar")
        build_jar_dst = os.path.join(dst_oss_fuzz_project.project_folder,
                                     "build-jar")
        shutil.copy(ant_path, ant_dst)
        shutil.copy(maven_path, maven_dst)
        shutil.copy(gradle_path, gradle_dst)
        shutil.copy(protoc_path, protoc_dst)
        shutil.copytree(build_jar_path, build_jar_dst)

    utils.copy_oss_fuzz_project_source(oss_fuzz_base_project,
                                       dst_oss_fuzz_project)

    # Log dir
    idx_logdir = os.path.join(auto_fuzz_proj_dir, "autofuzz-log")
    os.mkdir(idx_logdir)

    # Patch the fuzzer in the auto-fuzz directory according to the target
    # we want to validate.
    possible_target = possible_targets[idx]
    fuzzer_source = possible_target.generate_patched_fuzzer(
        oss_fuzz_base_project.base_fuzzer)
    with open(dst_oss_fuzz_project.base_fuzzer, "w") as file:
        file.write(fuzzer_source)

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
    summary['imports_to_add'] = list(possible_target.imports_to_add)
    summary['exceptions_to_handle'] = list(
        possible_target.exceptions_to_handle)
    summary['heuristics-used'] = list()
    for heuristic in possible_target.heuristics_used:
        summary['heuristics-used'].append(heuristic)
    with open(os.path.join(auto_fuzz_proj_dir, "result.json"),
              "w") as summary_file:
        json.dump(summary, summary_file)

    # Change build.sh and Dockerfile back to normal
    dst_oss_fuzz_project.change_dockerfile(jdk, project_build_type)
    dst_oss_fuzz_project.change_build_script(project_build_type)

    # Cleanup oss-fuzz artifacts
    oss_fuzz_manager.cleanup_project(os.path.basename(auto_fuzz_proj_dir),
                                     OSS_FUZZ_BASE)
    utils.cleanup_base_directory(auto_fuzz_proj_dir,
                                 os.path.basename(auto_fuzz_proj_dir))

    # Cleanup source code folders in auto fuzz dir and in oss-fuzz dir.
    for src_dir in os.listdir(auto_fuzz_proj_dir):
        full_path = os.path.join(auto_fuzz_proj_dir, src_dir)
        if not os.path.isdir(full_path):
            continue

        files_to_cleanup = ['ant.zip', 'maven.zip', 'gradle.zip', 'protoc.zip']
        for filename in files_to_cleanup:
            # Auto-fuzz path
            autofuzz_filename_path = os.path.join(auto_fuzz_proj_dir, filename)
            if os.path.isfile(autofuzz_filename_path):
                os.remove(autofuzz_filename_path)

            # OSS-Fuzz directory path
            ossfuzz_filename_path = os.path.join(
                OSS_FUZZ_BASE, "projects",
                os.path.basename(auto_fuzz_proj_dir), filename)
            if os.path.isfile(ossfuzz_filename_path):
                os.remove(ossfuzz_filename_path)

        if dst_oss_fuzz_project.project_name not in src_dir:
            continue

        # Clean drectory in auto-fuzz dir
        shutil.rmtree(full_path)

        # Clean up the directory in oss-fuzz
        oss_fuzz_path = os.path.join(OSS_FUZZ_BASE, "projects",
                                     os.path.basename(auto_fuzz_proj_dir),
                                     src_dir)

        if os.path.isdir(oss_fuzz_path):
            shutil.rmtree(oss_fuzz_path)

    tick_tqdm_tracker()


def run_builder_pool(autofuzz_base_workdir,
                     oss_fuzz_base_project,
                     possible_targets,
                     max_targets_to_analyse,
                     language,
                     benchmark=False,
                     project_build_type=None,
                     jdk="jdk15"):
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
            (idx_folder, idx, oss_fuzz_base_project, possible_targets,
             language, benchmark, project_build_type, jdk))

    print("Launching multi-threaded processing")
    print("Jobs completed:")
    try:
        # Allow failing here in the event tqdm is not present
        tqdm_tracker = tqdm.tqdm(
            total=min(max_targets_to_analyse, len(possible_targets)))
    except:
        pass

    # Run in batches of 10
    all_batches = [
        arg_list[x:x + constants.BATCH_SIZE_BEFORE_DOCKER_CLEAN] for x in
        range(0, len(arg_list), constants.BATCH_SIZE_BEFORE_DOCKER_CLEAN)
    ]
    for curr_batch in all_batches:
        pool = ThreadPool(constants.MAX_THREADS)
        pool.starmap(build_and_test_single_possible_target, curr_batch)
        pool.close()
        pool.join()

        # Cleanup docker
        utils.cleanup_build_cache()

    try:
        tqdm_tracker.close()
    except:
        pass


def autofuzz_project_from_github(github_url,
                                 language,
                                 do_static_analysis=False,
                                 possible_targets=None,
                                 to_merge=False,
                                 param_combination=False,
                                 benchmark=False):
    """Auto-generates fuzzers for a Github project and performs runtime checks
    on the fuzzers.
    """
    print("Running autofuzz on %s" % (github_url))
    base_dir = os.getcwd()
    autofuzz_base_workdir = utils.get_next_project_folder(base_dir=base_dir)
    os.mkdir(autofuzz_base_workdir)

    #autofuzz_data_dir = os.path.join(autofuzz_base_workdir, "base-autofuzz")
    base_oss_fuzz_project_dir = os.path.join(autofuzz_base_workdir,
                                             "base-autofuzz")
    os.mkdir(base_oss_fuzz_project_dir)

    # Create a OSS-Fuzz project abstraction for the base project.
    # A lot of derivatives will be created based off of this base project.
    oss_fuzz_base_project = OSS_FUZZ_PROJECT(base_oss_fuzz_project_dir,
                                             github_url, language, benchmark)

    # Clone the target and store it in our base OSS-Fuzz project. We need to get
    # the source for both static analysis and also for running each OSS-Fuzz
    # experiment. We store it like this to avoid having "git clone" in each
    # experiment, but rather using Docker's COPY.
    # If benchmark option is true, instead of cloning the project from github,
    # copy the local benchmark directory of the chosen language instead.
    if benchmark:
        if not utils.copy_benchmark_project(
                base_dir, github_url, language,
                os.path.join(oss_fuzz_base_project.project_folder,
                             oss_fuzz_base_project.project_name)):
            return False
    else:
        if not utils.git_clone_project(
                github_url,
                os.path.join(oss_fuzz_base_project.project_folder,
                             oss_fuzz_base_project.project_name)):
            return False

    # Download required files so we don't have to do it for each project.
    for file in constants.FILE_TO_PREPARE[language]:
        url = constants.FILE_TO_PREPARE[language][file]
        target_ant_path = os.path.join(oss_fuzz_base_project.project_folder,
                                       "%s.zip" % file)
        with open(target_ant_path, 'wb') as zip_file:
            zip_file.write(requests.get(url).content)

    static_res = None
    jdk_base = None
    jdk = "jdk15"
    if do_static_analysis:
        print("Running static analysis on %s" % (github_url))
        static_res, jdk_base, project_build_type = run_static_analysis(
            oss_fuzz_base_project, base_oss_fuzz_project_dir)

        # Clean static analysis oss-fuzz directory
        oss_fuzz_manager.cleanup_project(
            os.path.basename(oss_fuzz_base_project.project_folder),
            OSS_FUZZ_BASE)

        if jdk_base:
            # Overwrite dockerfile with correct jdk version
            # and avoid rebuild of project
            for key in constants.JDK_HOME:
                if constants.JDK_HOME[key] == jdk_base:
                    oss_fuzz_base_project.change_dockerfile(
                        key, project_build_type, False)
                    jdk = key
                    break

            # Change build.sh to avoid rebuild of project
            oss_fuzz_base_project.change_build_script(project_build_type,
                                                      False)

        if static_res:
            workdir = os.path.join(oss_fuzz_base_project.project_folder,
                                   "work")
            #commands.run_analysis_on_dir(target_folder=workdir,
            #                             coverage_url="",
            #                             analyses_to_run=[],
            #                             correlation_file="",
            #                             enable_all_analyses=True,
            #                             report_name="",
            #                             language=language,
            #                             output_json=[],
            #                             parallelise=False,
            #                             dump_files=False)
        else:
            utils.cleanup_base_directory(base_oss_fuzz_project_dir,
                                         oss_fuzz_base_project.project_name)
            return False

    # Check basic fuzzer and clean it afterwards
    res = oss_fuzz_manager.copy_and_build_project(
        oss_fuzz_base_project.project_folder,
        OSS_FUZZ_BASE,
        log_dir=base_oss_fuzz_project_dir)
    if not res:
        utils.cleanup_base_directory(base_oss_fuzz_project_dir,
                                     oss_fuzz_base_project.project_name)
        return False

    # Generate all possible targets
    if possible_targets is None:
        possible_targets = []
        if do_static_analysis and static_res:
            print("Generating fuzzers for %s" % (github_url))
            if language == "python":
                # Change build.sh and Dockerfile
                project_build_type = None
                oss_fuzz_base_project.change_dockerfile(
                    jdk, project_build_type)
                oss_fuzz_base_project.change_build_script(project_build_type)
                base_object = fuzz_driver_generation_python.PythonFuzzTarget()
            elif language == "java":
                base_object = fuzz_driver_generation_java.JavaFuzzTarget()

            projectdir = os.path.join(oss_fuzz_base_project.project_folder,
                                      oss_fuzz_base_project.project_name)
            class_list = utils.extract_class_list(projectdir)
            possible_targets_json_file = utils.generate_possible_targets(
                basedir, OSS_FUZZ_BASE, language,
                oss_fuzz_base_project.project_folder, class_list,
                param_combination)

    if possible_targets_json_file:
        with open(possible_targets_json_file, "r") as f:
            for possible_target_str in json.loads(f.read()):
                possible_target = copy.deepcopy(base_object)

                possible_target.from_json(possible_target_str)
                possible_targets.append(possible_target)

    print("Generated %d possible targets for %s." %
          (len(possible_targets), github_url))

    # Run all of the builders
    print("Running runtime checking on %d fuzzers for %s" % (min(
        constants.MAX_FUZZERS_PER_PROJECT, len(possible_targets)), github_url))
    run_builder_pool(autofuzz_base_workdir, oss_fuzz_base_project,
                     possible_targets, constants.MAX_FUZZERS_PER_PROJECT,
                     language, benchmark, project_build_type, jdk)

    if to_merge:
        merged_directory = post_process.merge_run(autofuzz_base_workdir,
                                                  language)
        if merged_directory:
            oss_fuzz_manager.copy_and_introspect_project(
                merged_directory, OSS_FUZZ_BASE, merged_directory)
            introspector_oss_base = os.path.join(
                OSS_FUZZ_BASE, "build", "out",
                os.path.basename(merged_directory), "introspector-report")
            if os.path.isdir(introspector_oss_base):
                print("Copying over introspector report")
                shutil.copytree(
                    introspector_oss_base,
                    os.path.join(merged_directory, "introspector-report"))
            else:
                print("No introspector generated")
        else:
            print("Fail to merge project")

    # Clean base directory for the project
    print("Cleaning base directory for %s" % (github_url))
    utils.cleanup_base_directory(base_oss_fuzz_project_dir,
                                 oss_fuzz_base_project.project_name)

    return True


def run_on_projects(language,
                    repos_to_target,
                    to_merge=False,
                    param_combination=False,
                    benchmark=False):
    """Run autofuzz generation on a list of Github projects."""
    home_dir = os.getcwd()
    for repo in repos_to_target:
        os.chdir(home_dir)
        autofuzz_project_from_github(repo,
                                     language,
                                     do_static_analysis=True,
                                     to_merge=to_merge,
                                     param_combination=param_combination,
                                     benchmark=benchmark)
    print("Completed auto-fuzz generation on %d projects" %
          len(repos_to_target))


def run_stage_two(target_dir):
    success_runs = post_process.extract_ranked(target_dir,
                                               runs_to_rank=1000000)
    heuristic_dict = dict()
    possible_targets = fuzz_driver_generation_python.merge_stage_one_targets(
        success_runs)
    autofuzz_project_from_github(
        'https://github.com/executablebooks/markdown-it-py',
        'python',
        do_static_analysis=False,
        possible_targets=possible_targets)


def get_cmdline_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--language",
                        type=str,
                        help="The languaeg of the projects",
                        default='python')
    parser.add_argument("--targets",
                        type=str,
                        help="The targets to use",
                        default='constants')
    parser.add_argument(
        "--merge",
        action="store_true",
        help=("If set, will for each project combine all successful projects "
              "into a single OSS-Fuzz project and run Fuzz Introspector on "
              "this project."))
    parser.add_argument(
        "--param_combination",
        action="store_true",
        help=
        ("If set and if some method parameters can be generated with "
         "multiple ways, the auto-fuzz generator will create one target "
         "for each of the possible comibinations for parameter generation. "
         "Creating a set of possible target with same method call but different "
         "parameter generating combination. If this is not set, only one possible "
         "target is generated for each method call with the first parameter generating "
         "combination. Currently, this option is only processed for java project."
         ))
    parser.add_argument(
        "--benchmark",
        action="store_true",
        help=(
            "If set, the auto-fuzz process will be executed on the benchmark "
            "project instead of real project."))

    return parser


if __name__ == "__main__":
    parser = get_cmdline_parser()
    args = parser.parse_args()

    projects = utils.get_target_repos(args.targets, args.language,
                                      args.benchmark)

    if projects:
        run_on_projects(args.language, projects, args.merge,
                        args.param_combination, args.benchmark)
    else:
        print("Language not supported")
