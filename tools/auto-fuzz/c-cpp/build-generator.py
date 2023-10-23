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
import subprocess


class AutoBuildContainer:

    def __init__(self):
        self.list_of_commands = []
        self.heuristic_id = ""


class PureMakefileScanner:

    def __init__(self):
        self.matches_found = {
            'Makefile': [],
        }

    def match_files(self, file_list):
        for fi in file_list:
            base_file = os.path.basename(fi)
            for key in self.matches_found:
                if base_file == key:
                    self.matches_found[key].append(fi)

    def is_matched(self):
        for file_to_match in self.matches_found:
            matches = self.matches_found[file_to_match]
            if len(matches) == 0:
                return False
        return True

    def steps_to_build(self):
        abc = AutoBuildContainer()
        abc.list_of_commands = ['make']
        abc.heuristic_id = self.name + "1"
        yield abc

    @property
    def name(self):
        return "make"


class AutoRefConfScanner:

    def __init__(self):
        self.matches_found = {
            'configure.ac': [],
            'Makefile.am': [],
        }

    def match_files(self, file_list):
        for fi in file_list:
            base_file = os.path.basename(fi)
            for key in self.matches_found:
                if base_file == key:
                    self.matches_found[key].append(fi)

    def is_matched(self):
        for file_to_match in self.matches_found:
            matches = self.matches_found[file_to_match]
            if len(matches) == 0:
                return False
        return True

    def steps_to_build(self):
        cmds_to_exec_from_root = ["autoreconf -fi", "./configure", "make"]
        abc = AutoBuildContainer()
        abc.list_of_commands = cmds_to_exec_from_root
        abc.heuristic_id = self.name + "1"
        yield abc

    @property
    def name(self):
        return "autogen"


class AutogenScanner:

    def __init__(self):
        self.matches_found = {
            'configure.ac': [],
            'Makefile': [],
        }

    def match_files(self, file_list):
        for fi in file_list:
            base_file = os.path.basename(fi)
            for key in self.matches_found:
                if base_file == key:
                    self.matches_found[key].append(fi)

    def is_matched(self):
        for file_to_match in self.matches_found:
            matches = self.matches_found[file_to_match]
            if len(matches) == 0:
                return False
        return True

    def steps_to_build(self):
        cmds_to_exec_from_root = [
            "autoconf", "autoheader", "./configure", "make"
        ]
        #yield cmds_to_exec_from_root
        abc = AutoBuildContainer()
        abc.list_of_commands = cmds_to_exec_from_root
        abc.heuristic_id = self.name + "1"
        yield abc

    @property
    def name(self):
        return "autogen"


class CMakeScanner:

    def __init__(self):
        self.matches_found = {
            'CMakeLists.txt': [],
        }

        self.cmake_options = set()

    def match_files(self, file_list):
        for fi in file_list:
            base_file = os.path.basename(fi)
            #print("Checking %s"%(base_file))
            for key in self.matches_found:
                if base_file == key:
                    self.matches_found[key].append(fi)

                    with open(fi, "r") as f:
                        content = f.read()
                    for line in content.split("\n"):
                        if "option(" in line:
                            option = line.split("option(")[1].split(" ")[0]
                            self.cmake_options.add(option)

        if len(self.cmake_options) > 0:
            print("Options:")
            for option in self.cmake_options:
                print("%s" % (option))

    def is_matched(self):
        for file_to_match in self.matches_found:
            matches = self.matches_found[file_to_match]
            if len(matches) == 0:
                return False
        return True

    def steps_to_build(self):
        # When we are running this, we are confident there are
        # some heuristics that match what is needed for cmake builds.
        # At this point, we will also scan for potential options
        # in the cmake files, such as:
        # - options related to shared libraries.
        # - options related to which packags need installing.
        cmds_to_exec_from_root = [
            "mkdir fuzz-build", "cd fuzz-build", "cmake ../", "make"
        ]
        abc = AutoBuildContainer()
        abc.list_of_commands = cmds_to_exec_from_root
        abc.heuristic_id = self.name + "1"
        yield abc

        opt1 = [
            "mkdir fuzz-build", "cd fuzz-build",
            "cmake -DCMAKE_CXX_COMPILER=$CXX -DCMAKE_CXX_FLAGS=\"$CXXFLAGS\" ../",
            "make"
        ]
        abc1 = AutoBuildContainer()
        abc1.list_of_commands = opt1
        abc1.heuristic_id = self.name + "2"
        yield abc1

        # Look for a heristic that is often used for disabling dynamic shared libraries.
        option_values = []
        for option in self.cmake_options:
            if "BUILD_SHARED_LIBS" == option:
                option_values.append("-D%s=OFF" % (option))
            elif "BUILD_STATIC" == option:
                option_values.append("-D%s=ON" % (option))
            elif "BUILD_SHARED" == option:
                option_values.append("-D%s=OFF" % (option))
            elif "ENABLE_STATIC" == option:
                option_values.append("-D%s=ON" % (option))

        if len(option_values) > 0:
            option_string = " ".join(option_values)
            bopt = [
                "mkdir fuzz-build", "cd fuzz-build",
                "cmake -DCMAKE_CXX_COMPILER=$CXX -DCMAKE_CXX_FLAGS=\"$CXXFLAGS\" %s ../"
                % (option_string), "make"
            ]
            abc2 = AutoBuildContainer()
            abc2.list_of_commands = bopt
            abc2.heuristic_id = self.name + "3"
            yield abc2

    @property
    def name(self):
        return "cmake"


def gen_build_script(commands_to_exec):
    build_script = ""
    for cmd in commands_to_exec:
        build_script += cmd + "\n"

    return build_script


def get_all_files_in_path(path, path_to_subtract=None):
    all_files = []
    if path_to_subtract == None:
        path_to_subtract = os.getcwd()
    for root, dirs, files in os.walk(path):
        for fi in files:
            path = os.path.join(root, fi)
            if path.startswith(path_to_subtract):
                path = path[len(path_to_subtract):]
            if len(path) > 0 and path[0] == '/':
                path = path[1:]
            all_files.append(path)
    return all_files


def extract_build_files(path):
    all_files = get_all_files_in_path(path, path)

    executable_files = {
        'static-libs': [],
        'dynamic-libs': [],
        'object-files': []
    }
    for fil in all_files:
        if fil.endswith(".o"):
            executable_files['object-files'].append(fil)
        if fil.endswith(".a"):
            executable_files['static-libs'].append(fil)
        if fil.endswith(".so"):
            executable_files['dynamic-libs'].append(fil)
    return executable_files


def find_possible_build_systems(abspath_of_target):
    all_files = get_all_files_in_path(abspath_of_target)
    all_checks = [
        PureMakefileScanner(),
        AutogenScanner(),
        AutoRefConfScanner(),
        CMakeScanner(),
    ]

    for scanner in all_checks:
        scanner.match_files(all_files)
        if scanner.is_matched():
            print("Matched: %s" % (scanner.name))
            for auto_build_gen in scanner.steps_to_build():
                print("Build script: ")
                #print(gen_build_script(cmds_to_exec))

                yield auto_build_gen


def create_setup(test_dir, abc, abspath_of_target):
    build_script = "#!/bin/bash -eu\n"
    build_script += "rm -rf /%s\n" % (test_dir)
    build_script += "cp -rf %s %s\n" % (abspath_of_target, test_dir)
    build_script += "cd %s\n" % (test_dir)
    build_script += gen_build_script(abc.list_of_commands)

    return build_script


def setup(github_url, test_build_scripts=True):
    dst_folder = github_url.split("/")[-1]

    # clone the base project into a dedicated folder
    if not os.path.isdir(dst_folder):
        subprocess.check_call("git clone --recurse-submodules %s %s" %
                              (github_url, dst_folder),
                              shell=True)

    initial_executable_files = extract_build_files(
        os.path.abspath(os.path.join(os.getcwd(), dst_folder)))

    # record the path
    base_workdir = os.getcwd()
    abspath_of_target = os.path.join(os.getcwd(), dst_folder)

    all_build_suggestions = list(
        find_possible_build_systems(abspath_of_target))
    print("Found %d possible build suggestions" % (len(all_build_suggestions)))
    testing_base_dir = "test-fuzz-build-"

    all_build_scripts = []
    for idx in range(len(all_build_suggestions)):
        test_dir = os.path.abspath(
            os.path.join(os.getcwd(), testing_base_dir + str(idx)))
        build_suggestion = all_build_suggestions[idx]
        build_script = create_setup(test_dir, build_suggestion,
                                    abspath_of_target)
        all_build_scripts.append((build_script, test_dir, build_suggestion))

    # return now if we don't need to test build scripts
    if test_build_scripts == False:
        return

    # Check each of the build scripts.
    results = dict()
    for build_script, test_dir, build_suggestion in all_build_scripts:
        with open("/src/build.sh", "w") as bf:
            bf.write(build_script)
        try:
            subprocess.check_call("compile", shell=True)
            build_returned_error = False
        except subprocess.CalledProcessError:
            build_returned_error = True

        # We still check if we build any artifacts, as there is a change
        # we got the libraries we need even if the build threw an error.
        binary_files_build = extract_build_files(test_dir)

        new_binary_files = {
            'static-libs': [],
            'dynamic-libs': [],
            'object-files': []
        }
        for key in binary_files_build:
            for bfile in binary_files_build[key]:
                if bfile not in initial_executable_files[key]:
                    new_binary_files[key].append(bfile)

        print(binary_files_build['static-libs'])
        results[test_dir] = {
            'build-script': build_script,
            'executables-build': binary_files_build,
            'auto-build-setup': (build_script, test_dir, build_suggestion)
        }

    for test_dir in results:
        print("%s : %s : %s" %
              (results[test_dir]['auto-build-setup'][2].heuristic_id, test_dir,
               results[test_dir]['executables-build']['static-libs']))


if __name__ == "__main__":
    setup(sys.argv[1])
