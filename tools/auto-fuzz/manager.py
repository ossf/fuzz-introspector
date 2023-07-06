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
import zipfile
import threading
try:
    import tqdm
except ImportError:
    print("No tqdm module, skipping progress bar")

# temporary fix: adding fuzz-introspector to the system path
sys.path.insert(0, '../../src/')
from fuzz_introspector import commands

# Auto-fuzz modules
import base_files
import oss_fuzz_manager
import fuzz_driver_generation_python
import fuzz_driver_generation_jvm
import post_process

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
    "jvm": os.path.join(FUZZ_INTRO_BASE, "frontends", "java", "run.sh")
}

if not os.path.isdir(FUZZ_INTRO_BASE):
    raise Exception("Could not find fuzz introspector directory")

if not os.path.isfile(FUZZ_INTRO_MAIN["python"]):
    raise Exception("Could not find fuzz introspector runner for python")

if not os.path.isfile(FUZZ_INTRO_MAIN["jvm"]):
    raise Exception("Could not find fuzz introspector runner for java")

if not os.path.isdir(OSS_FUZZ_BASE):
    raise Exception("Could not find OSS-Fuzz directory")


class OSS_FUZZ_PROJECT:
    """Abstraction of OSS-Fuzz project.

    Provides helper methods for easily managing files and folders and
    operations on a given OSS-Fuzz project.
    """

    def __init__(self, project_folder, github_url, language, benchmark=False):
        self.project_folder = project_folder
        self.github_url = github_url
        self.language = language
        self.benchmark = benchmark

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
        if self.language == "python":
            return self.project_folder + "/fuzz_1.py"
        elif self.language == "jvm":
            return self.project_folder + "/Fuzz.java"
        else:
            # Temporary fail safe logic
            return self.project_folder + "/fuzz_1.py"

    @property
    def oss_fuzz_project_name(self):
        return os.path.basename(self.project_folder)

    @property
    def oss_fuzz_fuzzer_namer(self):
        if self.language == "python":
            return os.path.basename(self.base_fuzzer).replace(".py", "")
        elif self.language == "jvm":
            return os.path.basename(self.base_fuzzer).replace(".java", "")
        else:
            # Temporary fail safe logic
            return os.path.basename(self.base_fuzzer).replace(".py", "")

    @property
    def project_name(self):
        if self.benchmark:
            return "%s-%s" % (self.language, self.github_url)
        else:
            # Simplify url by cutting https out, then assume what we have left is:
            # HTTP Type
            # github.com/{user}/{proj_name}
            # or
            # SSH Type
            # git@github.com:{user}/{proj_name}
            if self.github_url.startswith("https://"):
                return self.github_url.replace("https://", "").split("/")[2]
            elif self.github_url.startswith("http://"):
                return self.github_url.replace("http://", "").split("/")[2]
            else:
                return self.github_url.split("/")[1]

    def write_basefiles(self):
        with open(self.build_script, "w") as bfile:
            bfile.write(base_files.gen_builder_1(self.language))

        with open(self.base_fuzzer, "w") as ffile:
            ffile.write(base_files.gen_base_fuzzer(self.language))

        with open(self.project_yaml, "w") as yfile:
            yfile.write(
                base_files.gen_project_yaml(self.github_url, self.language))

        with open(self.dockerfile, "w") as dfile:
            dfile.write(
                base_files.gen_dockerfile(self.github_url, self.project_name,
                                          self.language))


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


def run_static_analysis_python(git_repo, basedir, project_name):
    possible_imports = set()
    curr_dir = os.getcwd()
    os.chdir(basedir)
    os.mkdir("work")
    os.chdir("work")

    # Copy the project directory from the basedir
    try:
        shutil.copytree(os.path.join(basedir, project_name),
                        os.path.join(os.getcwd(), project_name),
                        symlinks=True)
    except:
        print("Fail to retrieve github directory.")
        return False

    cmd = [
        "python3", FUZZ_INTRO_MAIN["python"], "--fuzzer", "../fuzz_1.py",
        "--package=%s" % (os.getcwd())
    ]
    ret = run_cmd(" ".join(cmd), 1800)
    if not os.path.isfile("fuzzerLogFile-fuzz_1.data.yaml"):
        ret = False
    ret = True

    os.chdir(curr_dir)
    return ret


def _ant_build_project(basedir, projectdir):
    """Helper method to build project using ant"""
    # Prepare ant
    with zipfile.ZipFile(os.path.join(basedir, "ant.zip"), "r") as af:
        af.extractall(basedir)

    # Set environment variable
    env_var = os.environ.copy()
    env_var['JAVA_HOME'] = os.path.join(basedir, "jdk-15", "jdk-15.0.2")
    env_var['PATH'] = os.path.join(
        basedir, constants.ANT_PATH) + ":" + os.path.join(
            basedir, constants.PROTOC_PATH) + ":" + env_var['PATH']

    # Build project with ant
    cmd = "chmod +x %s/ant && ant" % os.path.join(basedir, constants.ANT_PATH)
    try:
        subprocess.check_call(cmd,
                              shell=True,
                              timeout=1800,
                              stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL,
                              env=env_var,
                              cwd=projectdir)
    except subprocess.TimeoutExpired:
        return False
    except subprocess.CalledProcessError:
        return False

    return True


def _maven_build_project(basedir, projectdir):
    """Helper method to build project using maven"""
    # Prepare maven
    with zipfile.ZipFile(os.path.join(basedir, "maven.zip"), "r") as mf:
        mf.extractall(basedir)

    # Set environment variable
    env_var = os.environ.copy()
    env_var['JAVA_HOME'] = os.path.join(basedir, "jdk-15", "jdk-15.0.2")
    env_var['PATH'] = os.path.join(
        basedir, constants.MAVEN_PATH) + ":" + os.path.join(
            basedir, constants.PROTOC_PATH) + ":" + env_var['PATH']

    # Patch pom.xml to use at least jdk 1.8
    cmd = [
        "find ./ -name pom.xml -exec sed -i 's/compilerVersion>1.5</compilerVersion>1.8</g' {} \;",
        "find ./ -name pom.xml -exec sed -i 's/compilerVersion>1.6</compilerVersion>1.8</g' {} \;",
        "find ./ -name pom.xml -exec sed -i 's/source>1.5</source>1.8</g' {} \;",
        "find ./ -name pom.xml -exec sed -i 's/source>1.6</source>1.8</g' {} \;",
        "find ./ -name pom.xml -exec sed -i 's/target>1.5</target>1.8</g' {} \;",
        "find ./ -name pom.xml -exec sed -i 's/target>1.6</target>1.8</g' {} \;",
        "find ./ -name pom.xml -exec sed -i 's/java15/java18/g' {} \;",
        "find ./ -name pom.xml -exec sed -i 's/java16/java18/g' {} \;",
        "find ./ -name pom.xml -exec sed -i 's/java-1.5/java-1.8/g' {} \;",
        "find ./ -name pom.xml -exec sed -i 's/java-1.6/java-1.8/g' {} \;"
    ]
    try:
        subprocess.check_call(";".join(cmd),
                              shell=True,
                              timeout=1800,
                              stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL,
                              env=env_var,
                              cwd=projectdir)
    except subprocess.TimeoutExpired:
        return False
    except subprocess.CalledProcessError:
        return False

    # Build project with maven with default jdk
    cmd = [
        "mvn clean package dependency:copy-dependencies", "-DskipTests",
        "-Dmaven.javadoc.skip=true", "--update-snapshots",
        "-DoutputDirectory=lib", "-Dpmd.skip=true", "-Dencoding=UTF-8",
        "-Dmaven.antrun.skip=true"
    ]
    try:
        subprocess.check_call(" ".join(cmd),
                              shell=True,
                              timeout=1800,
                              stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL,
                              env=env_var,
                              cwd=projectdir)
    except subprocess.TimeoutExpired:
        return False
    except subprocess.CalledProcessError:
        return False

    return True


def _gradle_build_project(basedir, projectdir):
    """Helper method to build project using maven"""
    # Prepare gradle
    with zipfile.ZipFile(os.path.join(basedir, "gradle.zip"), "r") as gf:
        gf.extractall(basedir)

    # Set environment variable
    env_var = os.environ.copy()
    env_var['GRADLE_HOME'] = os.path.join(basedir, constants.GRADLE_HOME)
    env_var['JAVA_HOME'] = os.path.join(basedir, "jdk-15", "jdk-15.0.2")
    env_var['PATH'] = os.path.join(
        basedir, constants.GRADLE_PATH) + ":" + os.path.join(
            basedir, constants.PROTOC_PATH) + ":" + env_var['PATH']

    # Build project with maven
    cmd = [
        "chmod +x gradlew",
        """if ./gradlew tasks --all | grep -qw "^spotlessCheck";
        then
          ./gradlew clean build -x test -x spotlessCheck;
        else
          ./gradlew clean build -x test;
        fi""", "./gradlew --stop"
    ]
    try:
        subprocess.check_call(" && ".join(cmd),
                              shell=True,
                              timeout=1800,
                              stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL,
                              env=env_var,
                              cwd=projectdir)
    except subprocess.TimeoutExpired:
        return False
    except subprocess.CalledProcessError:
        return False

    # Search for possible classes location
    possible_build_path = []
    for root, dirs, _ in os.walk("."):
        for dir in dirs:
            build_path = os.path.join(root, dir, "build", "classes", "java",
                                      "main")
            jar_path = os.path.join(root, dir, "build", "libs")
            if os.path.exists(build_path) and not os.path.exists(jar_path):
                possible_build_path.append(os.path.abspath(build_path))

    # Add in jar packing command for all possible build path
    cmd = []
    for build_path in possible_build_path:
        if os.path.exists("proj.jar"):
            cmd.append("jar uvf proj.jar -C %s ." % build_path)
        else:
            cmd.append("jar cvf proj.jar -C %s ." % build_path)
    try:
        if cmd:
            subprocess.check_call(" && ".join(cmd),
                                  shell=True,
                                  timeout=1800,
                                  stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL,
                                  cwd=projectdir)
    except subprocess.TimeoutExpired:
        return False
    except subprocess.CalledProcessError as e:
        return False

    return True


def find_project_build_folder(dir, proj_name):
    # Search for current directory first
    currdir = os.listdir(dir)
    if "pom.xml" in currdir or "build.gradle" in currdir or "build.xml" in currdir or "build.gradle.kts" in currdir:
        return os.path.abspath(dir)

    # Search for sub directory with name same as project name
    for subdir in currdir:
        if os.path.isdir(os.path.join(dir, subdir)) and subdir == proj_name:
            subdir_list = os.listdir(os.path.join(dir, subdir))
            if "pom.xml" in subdir_list or "build.gradle" in subdir_list or "build.xml" in subdir_list or "build.gradle.kts" in currdir:
                return os.path.abspath(os.path.join(dir, subdir))

    # Recursively look for subdirectory that contains build property file
    for root, _, files in os.walk(dir):
        if "pom.xml" in files or "build.gradle" in files or "build.xml" in files or "build.gradle.kts" in files:
            return os.path.abspath(root)

    return None


def build_jvm_project(basedir, projectdir, proj_name):
    # Find project subfolder if build properties not in the outtermost
    # directory
    builddir = find_project_build_folder(projectdir, proj_name)

    # Prepare OpenJDK 15
    os.makedirs(os.path.join(basedir, "jdk-15"), exist_ok=True)
    with tarfile.open(os.path.join(basedir, "jdk.tar.gz"), "r:gz") as jf:
        jf.extractall(os.path.join(basedir, "jdk-15"))

    # Prepare protoc
    os.makedirs(os.path.join(basedir, "protoc"), exist_ok=True)
    with zipfile.ZipFile(os.path.join(basedir, "protoc.zip"), "r") as pf:
        pf.extractall(os.path.join(basedir, "protoc"))
    protoc_executable = os.path.join(basedir, "protoc", "bin", "protoc")
    base_stat = os.stat(protoc_executable)
    os.chmod(os.path.join(basedir, "protoc", "bin", "protoc"),
             base_stat.st_mode | stat.S_IEXEC)

    if builddir:
        if os.path.exists(os.path.join(builddir, "pom.xml")):
            # Maven project
            build_ret = _maven_build_project(basedir, builddir)
            return ("maven", build_ret, builddir, [])
        elif os.path.exists(os.path.join(
                builddir, "build.gradle")) or os.path.exists(
                    os.path.join(builddir, "build.gradle.kts")):
            # Gradle project
            build_ret = _gradle_build_project(basedir, builddir)
            if os.path.exists(os.path.join(builddir, "proj.jar")):
                jarfiles = [os.path.join(builddir, "proj.jar")]
            else:
                jarfiles = []
            return ("gradle", build_ret, builddir, jarfiles)
        elif os.path.exists(os.path.join(builddir, "build.xml")):
            # Ant project
            build_ret = _ant_build_project(basedir, builddir)
            return ("ant", build_ret, builddir, [])

    # Unknown project type
    return (None, False, None, None)


def run_static_analysis_jvm(git_repo, basedir, project_name):
    possible_imports = set()
    curr_dir = os.getcwd()
    os.chdir(basedir)
    os.mkdir("work")
    os.chdir("work")
    os.mkdir("jar")

    # Copy the project directory from the basedir
    try:
        shutil.copytree(os.path.join(basedir, project_name),
                        os.path.join(os.getcwd(), "proj"),
                        symlinks=True)
    except:
        print("Fail to retrieve github directory.")
        return False

    jardir = os.path.join(basedir, "work", "jar")
    projectdir = os.path.join(basedir, "work", "proj")

    project_type, build_ret, builddir, jarfiles = build_jvm_project(
        basedir, projectdir, project_name)

    if not build_ret:
        print("Unknown project type or project build fail.\n")
        return False

    # Retrieve Jazzer package for building fuzzer
    jazzer_url = "https://github.com/CodeIntelligenceTesting/jazzer/releases/download/v0.15.0/jazzer-linux.tar.gz"
    response = requests.get(jazzer_url)
    with open("./jazzer.tar.gz", "wb") as f:
        f.write(response.content)

    with tarfile.open("./jazzer.tar.gz") as f:
        f.extractall("./")

    # Retrieve Apache Common Lang3 package
    # This library provides method to translate primitive type arrays to
    # their respective class object arrays to avoid compilation error.
    apache_url = "https://repo1.maven.org/maven2/org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.jar"
    response = requests.get(apache_url)
    with open("./commons-lang3.jar", "wb") as f:
        f.write(response.content)

    # Retrieve path of all jar files
    jarfiles.append(os.path.abspath("../Fuzz.jar"))
    jarfiles.append("%s/*.jar" % jardir)
    jarfiles_no_dependency = []
    jarfiles_no_dependency.extend(jarfiles)
    jarfiles.append("%s/lib/*.jar" % jardir)
    if project_type == "ant":
        for file in os.listdir(os.path.join(builddir, "build", "jar")):
            if file.endswith(".jar"):
                shutil.copyfile(os.path.join(builddir, "build", "jar", file),
                                os.path.join(jardir, file))
    else:
        os.makedirs("%s/lib" % jardir, exist_ok=True)
        for root, _, files in os.walk(builddir):
            for file in [file for file in files if file.endswith(".jar")]:
                if "test" not in file and "sources" not in file:
                    if root.endswith("lib"):
                        dst_path = os.path.join(jardir, "lib", file)
                    else:
                        dst_path = os.path.join(jardir, file)
                    shutil.copyfile(os.path.abspath(os.path.join(root, file)),
                                    dst_path)

    # Compile and package fuzzer to jar file
    cmd = [
        "javac -cp jazzer_standalone.jar:commons-lang3.jar:%s ../Fuzz.java" %
        ":".join(jarfiles), "jar cvf ../Fuzz.jar ../Fuzz.class"
    ]
    try:
        subprocess.check_call(" && ".join(cmd),
                              shell=True,
                              timeout=600,
                              stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        print("Fail to compile Fuzz.java.\n")
        return False

    # Run the java frontend static analysis
    cmd = [
        "./run.sh", "--jarfile", ":".join(jarfiles_no_dependency),
        "--entryclass", "Fuzz", "--src", projectdir, "--autofuzz"
    ]
    try:
        subprocess.check_call(" ".join(cmd),
                              shell=True,
                              timeout=1800,
                              stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL,
                              cwd=os.path.dirname(FUZZ_INTRO_MAIN["jvm"]))
    except subprocess.TimeoutExpired:
        print("Fail to execute java frontend code.\n")
        return False
    except subprocess.CalledProcessError:
        print("Fail to execute java frontend code.\n")
        return False

    # Move data and data.yaml to working directory
    data_src = os.path.join(os.path.dirname(FUZZ_INTRO_MAIN["jvm"]),
                            "fuzzerLogFile-Fuzz.data")
    yaml_src = os.path.join(os.path.dirname(FUZZ_INTRO_MAIN["jvm"]),
                            "fuzzerLogFile-Fuzz.data.yaml")
    data_dst = os.path.join(basedir, "work", "fuzzerLogFile-Fuzz.data")
    yaml_dst = os.path.join(basedir, "work", "fuzzerLogFile-Fuzz.data.yaml")
    if os.path.isfile(data_src) and os.path.isfile(yaml_src):
        ret = True
        try:
            shutil.copy(data_src, data_dst)
            shutil.copy(yaml_src, yaml_dst)
        except:
            print("Fail to execute java frontend code.\n")
            ret = False
    else:
        print("Fail to execute java frontend code.\n")
        ret = False

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


def tick_tqdm_tracker():
    global tqdm_tracker
    try:
        tqdm_tracker.update(1)
    except:
        return


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
        'protoc.zip', 'jdk.tar.gz', 'work/commons-lang3.jar', 'work/jazzer',
        'work/jazzer.tar.gz', 'work/jazzer_standalone.jar'
    ]
    dir_to_clean = [
        'apache-maven-3.6.3', 'apache-ant-1.9.16', 'gradle-7.4.2', 'jdk-15',
        'protoc', project_name, 'work/jar', 'work/proj'
    ]

    for file in file_to_clean:
        if os.path.isfile(os.path.join(base_dir, file)):
            os.remove(os.path.join(base_dir, file))

    for dir in dir_to_clean:
        if os.path.isdir(os.path.join(base_dir, dir)):
            shutil.rmtree(os.path.join(base_dir, dir))


def build_and_test_single_possible_target(idx_folder,
                                          idx,
                                          oss_fuzz_base_project,
                                          possible_targets,
                                          language,
                                          benchmark,
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
    copy_core_oss_fuzz_project_files(oss_fuzz_base_project,
                                     dst_oss_fuzz_project)
    if language == "jvm":
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
        shutil.copy(ant_path, ant_dst)
        shutil.copy(maven_path, maven_dst)
        shutil.copy(gradle_path, gradle_dst)
        shutil.copy(protoc_path, protoc_dst)

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
    summary['imports_to_add'] = list(possible_target.imports_to_add)
    summary['exceptions_to_handle'] = list(
        possible_target.exceptions_to_handle)
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
                     benchmark=False):
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
        arg_list.append((idx_folder, idx, oss_fuzz_base_project,
                         possible_targets, language, benchmark))

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
        cleanup_build_cache()

    try:
        tqdm_tracker.close()
    except:
        pass


def copy_benchmark_project(base_dir, benchmark, language, destination):
    shutil.copytree(os.path.join(base_dir, "benchmark", language, benchmark),
                    destination)
    return True


def git_clone_project(github_url, destination):
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
    autofuzz_base_workdir = get_next_project_folder(base_dir=base_dir)
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
        if not copy_benchmark_project(
                base_dir, github_url, language,
                os.path.join(oss_fuzz_base_project.project_folder,
                             oss_fuzz_base_project.project_name)):
            return False
    else:
        if not git_clone_project(
                github_url,
                os.path.join(oss_fuzz_base_project.project_folder,
                             oss_fuzz_base_project.project_name)):
            return False

    # If this is a jvm target download ant, maven and gradle once so we don't
    # have to do it for each proejct. Also extract a class_list for java classes
    # in the repository before building the project. This class_list is used for
    # target method filtering in the target generation stage. Some project requires
    # protoc to generate java code, so protoc is also downloaded here.
    if language == "jvm":
        # Download OpenJDK 15:
        target_jdk_path = os.path.join(oss_fuzz_base_project.project_folder,
                                       "jdk.tar.gz")
        with open(target_jdk_path, 'wb') as jf:
            jf.write(requests.get(constants.JDK_URL).content)
        # Download Ant
        target_ant_path = os.path.join(oss_fuzz_base_project.project_folder,
                                       "ant.zip")
        with open(target_ant_path, 'wb') as mf:
            mf.write(requests.get(constants.ANT_URL).content)

        # Download Maven
        target_maven_path = os.path.join(oss_fuzz_base_project.project_folder,
                                         "maven.zip")
        with open(target_maven_path, 'wb') as mf:
            mf.write(requests.get(constants.MAVEN_URL).content)

        # Download Gradle
        target_gradle_path = os.path.join(oss_fuzz_base_project.project_folder,
                                          "gradle.zip")
        with open(target_gradle_path, 'wb') as gf:
            gf.write(requests.get(constants.GRADLE_URL).content)

        # Download protoc
        target_protoc_path = os.path.join(oss_fuzz_base_project.project_folder,
                                          "protoc.zip")
        with open(target_protoc_path, 'wb') as gf:
            gf.write(requests.get(constants.PROTOC_URL).content)

        # Extract class list for the target project
        java_class_list = extract_class_list(
            os.path.join(oss_fuzz_base_project.project_folder,
                         oss_fuzz_base_project.project_name))

    # Generate the base Dockerfile, build.sh, project.yaml and fuzz_1.py
    oss_fuzz_base_project.write_basefiles()

    static_res = None
    if do_static_analysis:
        print("Running static analysis on %s" % (github_url))
        if language == "python":
            static_res = run_static_analysis_python(
                github_url, oss_fuzz_base_project.project_folder,
                oss_fuzz_base_project.project_name)
        elif language == "jvm":
            static_res = run_static_analysis_jvm(
                github_url, oss_fuzz_base_project.project_folder,
                oss_fuzz_base_project.project_name)

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
            return False

    # Check basic fuzzer and clean it afterwards
    res = oss_fuzz_manager.copy_and_build_project(
        oss_fuzz_base_project.project_folder,
        OSS_FUZZ_BASE,
        log_dir=base_oss_fuzz_project_dir,
        base_autofuzz=True)
    if not res:
        return False

    # Generate all possible targets
    if possible_targets is None:
        possible_targets = []
        if do_static_analysis and static_res:
            print("Generating fuzzers for %s" % (github_url))
            if language == "python":
                possible_targets = fuzz_driver_generation_python.generate_possible_targets(
                    oss_fuzz_base_project.project_folder)
            elif language == "jvm":
                possible_targets = fuzz_driver_generation_jvm.generate_possible_targets(
                    oss_fuzz_base_project.project_folder, java_class_list,
                    constants.MAX_TARGET_PER_PROJECT_HEURISTIC,
                    param_combination)

    print("Generated %d possible targets for %s." %
          (len(possible_targets), github_url))

    # Run all of the builders
    print("Running runtime checking on %d fuzzers for %s" % (min(
        constants.MAX_FUZZERS_PER_PROJECT, len(possible_targets)), github_url))
    run_builder_pool(autofuzz_base_workdir, oss_fuzz_base_project,
                     possible_targets, constants.MAX_FUZZERS_PER_PROJECT,
                     language, benchmark)

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
    cleanup_base_directory(base_oss_fuzz_project_dir,
                           oss_fuzz_base_project.project_name)

    return True


def benchmark_on_projects(language,
                          benchmarks_to_target,
                          to_merge=False,
                          param_combination=False):
    """Run autofuzz generation on a list of local benchmark."""
    home_dir = os.getcwd()
    for benchmark in benchmarks_to_target:
        os.chdir(home_dir)
        autofuzz_project_from_github(benchmark,
                                     language,
                                     do_static_analysis=True,
                                     to_merge=to_merge,
                                     param_combination=param_combination,
                                     benchmark=True)
    print("Completed auto-fuzz generation on %d benchmarks" %
          len(benchmarks_to_target))


def run_on_projects(language,
                    repos_to_target,
                    to_merge=False,
                    param_combination=False):
    """Run autofuzz generation on a list of Github projects."""
    home_dir = os.getcwd()
    for repo in repos_to_target:
        os.chdir(home_dir)
        autofuzz_project_from_github(repo,
                                     language,
                                     do_static_analysis=True,
                                     to_merge=to_merge,
                                     param_combination=param_combination)
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


def get_target_repos(targets, language):
    if targets == "constants":
        return constants.git_repos[language]
    github_projects = []
    with open(args.targets, 'r') as f:
        for line in f:
            github_projects.append(line.replace("\n", "").strip())
    return github_projects


if __name__ == "__main__":
    parser = get_cmdline_parser()
    args = parser.parse_args()

    if args.language == 'python':
        if (args.benchmark):
            print("Benchmarking for python is not supported yet")
        else:
            github_projects = get_target_repos(args.targets, 'python')
            run_on_projects("python", github_projects, args.merge)
    elif args.language == 'java':
        if (args.benchmark):
            benchmark_projects = constants.benchmark['jvm']
            benchmark_on_projects("jvm", benchmark_projects, args.merge)
        else:
            github_projects = get_target_repos(args.targets, 'jvm')
            run_on_projects("jvm", github_projects, args.merge,
                            args.param_combination)
    else:
        print("Language not supported")
