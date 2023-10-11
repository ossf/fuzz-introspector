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

import constants
import os
import shutil
import subprocess


# Project preparation utils
###########################
def copy_benchmark_project(base_dir, benchmark, language, destination):
    """Copy benchmark project to destination"""
    shutil.copytree(os.path.join(base_dir, "benchmark", language, benchmark),
                    destination)
    return True


def git_clone_project(github_url, destination):
    """Clone project from github url to destination"""
    cmd = ["git clone", github_url, destination]
    try:
        subprocess.check_call(" ".join(cmd),
                              shell=True,
                              timeout=600,
                              stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        return False
    except subprocess.CalledProcessError:
        return False
    return True


def get_target_repos(targets, language):
    """Retrieve list of target proejct url"""
    if targets == "constants":
        return constants.git_repos[language]
    github_projects = []
    with open(args.targets, 'r') as f:
        for line in f:
            github_projects.append(line.replace("\n", "").strip())
    return github_projects


def get_next_project_folder(base_dir):
    """Auto-detect next available result directory name"""
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


# JVM Project discovery utils
#############################
def _find_dir_build_type(dir):
    """Determine the java build project type of the directory"""

    if os.path.exists(os.path.join(dir, "pom.xml")):
        return "maven"
    elif os.path.exists(os.path.join(dir, "build.gradle")) or os.path.exists(
            os.path.join(dir, "build.gradle.kts")):
        return "gradle"
    elif os.path.exists(os.path.join(dir, "build.xml")):
        return "ant"
    else:
        return None


def find_project_build_type(dir, proj_name):
    """Search for base project directory to detect project build type"""
    # Search for current directory first
    project_build_type = _find_dir_build_type(dir)
    if project_build_type:
        return project_build_type

    # Search for sub directory with name same as project name
    for subdir in os.listdir(dir):
        if os.path.isdir(os.path.join(dir, subdir)) and subdir == proj_name:
            project_build_type = _find_dir_build_type(os.path.join(
                dir, subdir))
            if project_build_type:
                return project_build_type

    # Recursively look for subdirectory that contains build property file
    for root, _, files in os.walk(dir):
        project_build_type = _find_dir_build_type(root)
        if project_build_type:
            return project_build_type

    return None, None


def extract_class_list(projectdir):
    """Extract a list of path for all java files exist in the project directory"""
    project_class_list = []

    for root, _, files in os.walk(projectdir):
        for file in [file for file in files if file.endswith(".java")]:
            path = os.path.join(root, file)
            path = path.replace("%s/" % projectdir, "")
            path = path.replace(".java", "").replace("/", ".")

            # Filter some unrelated class
            if "module-info" in path or "package-info" in path:
                continue
            if "test" in path or "Test" in path:
                continue
            if path.endswith("Exception"):
                continue

            if path not in project_class_list:
                project_class_list.append(path)

    return project_class_list


# OSS-Fuzz project copying utils
################################
def copy_core_oss_fuzz_project_files(src_oss_project, dst_oss_project):
    """Copy base OSS-Fuzz project file to destination directory"""
    shutil.copy(src_oss_project.build_script, dst_oss_project.build_script)
    shutil.copy(src_oss_project.project_yaml, dst_oss_project.project_yaml)
    shutil.copy(src_oss_project.dockerfile, dst_oss_project.dockerfile)


def copy_oss_fuzz_project_source(src_oss_project, dst_oss_project):
    """Copy OSS-Fuzz target project to destination directory"""
    shutil.copytree(
        os.path.join(src_oss_project.project_folder,
                     src_oss_project.project_name),
        os.path.join(dst_oss_project.project_folder,
                     dst_oss_project.project_name))


# Project cleaning utils
########################
def cleanup_build_cache():
    """Cleans up Docker build cache. This is needed becaus auto-fuzz builds
    up a large docker build cache, which can take up hundreds of GBs on a
    small run.
    """
    subprocess.check_call('docker builder prune --force',
                          shell=True,
                          stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL)


def cleanup_base_directory(base_dir, project_name):
    """Cleans up the base directory, removing unnecessary files after
    the fuzzers auto-generation and checking process.
    """
    file_to_clean = [
        'Fuzz.jar', 'Fuzz.class', 'ant.zip', 'gradle.zip', 'maven.zip',
        'protoc.zip', 'jdk15.tar.gz', 'jdk17.tar.gz', 'jdk11.tar.gz',
        'jdk8.tar.gz'
    ]
    dir_to_clean = [
        'apache-maven-3.6.3', 'apache-ant-1.10.13', 'gradle-7.4.2',
        'jdk-15.0.2', 'jdk-17', 'jdk-11.0.0.1', 'java-se-8u43-ri', 'protoc',
        project_name, 'work/jar', 'work/proj', 'build-jar'
    ]

    for file in file_to_clean:
        if os.path.isfile(os.path.join(base_dir, file)):
            os.remove(os.path.join(base_dir, file))

    for dir in dir_to_clean:
        if os.path.isdir(os.path.join(base_dir, dir)):
            shutil.rmtree(os.path.join(base_dir, dir))


# Local command execution
#########################
def run_cmd(cmd, timeout_sec):
    """Execute script in the local environment"""
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
