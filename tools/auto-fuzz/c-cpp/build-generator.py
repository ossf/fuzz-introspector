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
import shutil
import cxxfilt
import subprocess

CPP_BASE_TEMPLATE = """#include <stdint.h>
#include <iostream>

extern "C" int 
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    std::string input(reinterpret_cast<const char*>(data), size);

    // Insert fuzzer contents here 
    // input string contains fuzz input.

    // end of fuzzer contents

    return 0;
}"""


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
            "mkdir fuzz-build", "cd fuzz-build",
            "cmake -DCMAKE_VERBOSE_MAKEFILE=ON ../", "make V=1 || true"
        ]
        abc = AutoBuildContainer()
        abc.list_of_commands = cmds_to_exec_from_root
        abc.heuristic_id = self.name + "1"
        yield abc

        opt1 = [
            "mkdir fuzz-build", "cd fuzz-build",
            "cmake -DCMAKE_CXX_COMPILER=$CXX -DCMAKE_CXX_FLAGS=\"$CXXFLAGS\" ../",
            "make || true"
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
    build_script = "#!/bin/bash\n"
    build_script += "rm -rf /%s\n" % (test_dir)
    build_script += "cp -rf %s %s\n" % (abspath_of_target, test_dir)
    build_script += "cd %s\n" % (test_dir)
    build_script += gen_build_script(abc.list_of_commands)

    return build_script


def setup(github_url, test_build_scripts=True, build_fuzzer=True):
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

    if build_fuzzer == False:
        return
    # For each of the successful builds, try to link
    # an empty fuzzer against the build libraies.
    for test_dir in results:
        refined_static_list = []

        libs_to_avoid = {
            "libgtest.a", "libgmock.a", "libgmock_main.a", "libgtest_main.a"
        }
        for static_lib in results[test_dir]['executables-build'][
                'static-libs']:
            if any(
                    os.path.basename(static_lib) in lib_to_avoid
                    for lib_to_avoid in libs_to_avoid):
                continue
            refined_static_list.append(static_lib)

        results[test_dir]['refined-static-libs'] = refined_static_list

    for test_dir in results:
        print("Test dir: %s :: %s" %
              (test_dir, str(results[test_dir]['refined-static-libs'])))

        if len(results[test_dir]['refined-static-libs']) == 0:
            continue

        print("Trying to link in an empty fuzzer")

        empty_fuzzer_file = '/src/empty-fuzzer.cpp'
        with open(empty_fuzzer_file, "w") as f:
            f.write(CPP_BASE_TEMPLATE)

        # Try to link the fuzzer to the static libs
        cmd = [
            "clang++", "-fsanitize=fuzzer", "-fsanitize=address",
            empty_fuzzer_file
        ]
        for refined_static_lib in results[test_dir]['refined-static-libs']:
            cmd.append(os.path.join(test_dir, refined_static_lib))

        print("Command [%s]" % (" ".join(cmd)))

        try:
            subprocess.check_call(" ".join(cmd), shell=True)
            base_fuzz_build = True
        except subprocess.CalledProcessError:
            base_fuzz_build = False

        print("Base fuzz build: %s" % (str(base_fuzz_build)))

        results[test_dir]['base-fuzz-build'] = base_fuzz_build

    # We now know for which versions we can generate a base fuzzer.
    # Let's run an introspector build
    for test_dir in results:
        if results[test_dir]['base-fuzz-build'] == False:
            continue

        introspector_vanilla_build_script = results[test_dir]['build-script']

        empty_fuzzer_file = '/src/empty-fuzzer.cpp'
        with open(empty_fuzzer_file, "w") as f:
            f.write(CPP_BASE_TEMPLATE)

        # Try to link the fuzzer to the static libs
        cmd = ["$CXX", "$CXXFLAGS", "$LIB_FUZZING_ENGINE", empty_fuzzer_file]
        for refined_static_lib in results[test_dir]['refined-static-libs']:
            cmd.append(os.path.join(test_dir, refined_static_lib))

        introspector_vanilla_build_script += "\n%s" % (" ".join(cmd))

        with open("/src/build.sh", "w") as bs:
            bs.write(introspector_vanilla_build_script)

        modified_env = os.environ
        modified_env['SANITIZER'] = 'introspector'
        modified_env['FUZZ_INTROSPECTOR_AUTO_FUZZ'] = "1"
        modified_env['PROJECT_NAME'] = 'auto-fuzz-proj'
        modified_env['FUZZINTRO_OUTDIR'] = test_dir
        try:

            subprocess.check_call("compile", shell=True, env=modified_env)
            build_returned_error = False
        except subprocess.CalledProcessError:
            build_returned_error = True
        print("Introspector build: %s" % (str(build_returned_error)))

        # Now scan the diretory for relevant yaml files
        print("Introspection files found")
        all_files = get_all_files_in_path(test_dir)
        introspection_files_found = []
        all_header_files = []
        for yaml_file in all_files:
            if "allFunctionsWithMain" in yaml_file:
                print(yaml_file)
                introspection_files_found.append(yaml_file)
            if yaml_file.endswith(".h"):
                all_header_files.append(yaml_file)

        all_functions_in_project = []
        for fi_yaml_file in introspection_files_found:
            with open(fi_yaml_file, "r") as file:
                yaml_content = yaml.safe_load(file)

            for elem in yaml_content['All functions']['Elements']:
                all_functions_in_project.append(elem)

        print("Found a total of %d functions" %
              (len(all_functions_in_project)))
        for func in all_functions_in_project:
            try:
                demangled = cxxfilt.demangle(func['functionName'])
            except:
                demangled = func['functionName']

            src_file = func['functionSourceFile']
            if src_file.strip() == "":
                continue
            discarded_paths = {
                "googletest",
                "usr/local/bin",
            }
            to_cont = True
            for discarded_path in discarded_paths:
                if discarded_path in src_file:
                    to_cont = False
                    break
            if not to_cont:
                continue
            #print("{%s :: %s :: [%s] :: [%s]}"%(
            #    demangled,
            #    func['functionSourceFile'],
            #    str(func['argNames']),
            #    str(func['argTypes'])))

        # Identify easy heuristics
        print("Functions that we want to target")
        results_to_run = []
        functions_to_target = []
        for func in all_functions_in_project:
            valid_targets = 0
            for arg in func['argNames']:
                if arg == "":
                    continue
                valid_targets += 1
            if valid_targets > 2 or valid_targets == 0:
                continue

            #if len(func['argNames']) > valid_targets:
            func['refinedArgNames'] = func['argNames'][:valid_targets]
            func['refinedArgTypes'] = func['argTypes'][len(func['argTypes']) -
                                                       valid_targets:]

            # Target functions that only accept strings as arguments
            #for argType in func['refinedArgTypes']:
            #    if 'basic_string' not in argType:
            #        toCont = False

            # Check argType
            #if "basic_string" not in func['argTypes'][0]:
            #    continue
            if "this" in func['argNames'][0]:
                continue
            try:
                demangled = cxxfilt.demangle(func['functionName'])
            except:
                demangled = func['functionName']
            if "googletest" in func['functionSourceFile']:
                continue
            ##if "/usr/local/bin/" in func['functionSourceFile']:
            #    continue
            if "parse" not in demangled:
                continue
            func['demangled-name'] = demangled
            #print("{%s :: %s :: [%s] :: [%s]}"%(
            #    demangled,
            #    func['functionSourceFile'],
            #    str(func['argNames']),
            #    str(func['argTypes'])))
            functions_to_target.append(func)
            #print("Refined arguments:")
            #print("[[%s] :: [%s]]"%(str(func['refinedArgNames']), str(func['refinedArgTypes'])))

        print("Found %d targets" % (len(functions_to_target)))

        # Create the source code as well as build scripts
        for func in functions_to_target:
            # Generate a fuzz target
            # Create the string for the variables seeded with fuzz data.
            fuzzerArgNames = []
            fuzzerArgDefs = []
            idx = 0
            for argType in func['refinedArgTypes']:
                if 'basic_string' in argType:
                    fuzzerArgNames.append('a%d' % (idx))
                    fuzzerArgDefs.append(
                        'auto a%d = fdp.ConsumeRandomLengthString()' % (idx))
                idx += 1

            # Create the string for the function call into the target
            fuzzerTargetCall = '%s' % (func['demangled-name'].split("(")[0])
            fuzzerTargetCall += '('
            for idx2 in range(len(fuzzerArgDefs)):
                fuzzerTargetCall += fuzzerArgNames[idx2]
                if idx2 < (len(fuzzerArgDefs) - 1):
                    fuzzerTargetCall += ","
            fuzzerTargetCall += ')'

            # Generate the string for LLVMFuzzerTestOneInput
            print("Fuzzer target call: %s" % (fuzzerTargetCall))
            fuzzer_entrypoint_func = """
extern "C" int 
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);
            """
            fuzzer_entrypoint_func += "\n"
            # Fuzzer variable declarations
            for fuzzerArgDef in fuzzerArgDefs:
                fuzzer_entrypoint_func += "  " + fuzzerArgDef + ";\n"

            # Function call into the target
            fuzzer_entrypoint_func += "  " + fuzzerTargetCall + ";\n"
            fuzzer_entrypoint_func += "  return 0;\n"
            fuzzer_entrypoint_func += "}\n"

            print(fuzzer_entrypoint_func)

            # Generate string for importing relevant headers
            fuzzerImports = """#include <iostream>
#include <stdlib.h>
#include <fuzzer/FuzzedDataProvider.h>
"""

            # Identify which headers to include based on the files
            # in the source code folder.
            headers_to_include = set()
            header_paths_to_include = set()
            for header_file in all_header_files:
                #print("- %s"%(header_file))
                if "/test/" in header_file:
                    continue
                if "googletest" in header_file:
                    continue
                headers_to_include.add(os.path.basename(header_file))
                header_paths_to_include.add("/".join(
                    header_file.split("/")[1:-1]))

            # Generate strings for "#include" statements, to be used in the fuzzer
            # source code.
            fuzzerImports += "\n"
            for header_to_include in headers_to_include:
                fuzzerImports += "#include <%s>\n" % (header_to_include)

            # Generate -I strings to be used in the build command.
            build_command_includes = ""
            for header_path_to_include in header_paths_to_include:
                build_command_includes += "-I" + os.path.join(
                    test_dir, header_path_to_include) + " "

            # Assemble full fuzzer source code
            full_fuzzer_source = fuzzerImports + "\n" + fuzzer_entrypoint_func

            print(">>>>")
            print(full_fuzzer_source)
            print("<<<<")
            print("Build command includes: %s" % (build_command_includes))

            # Generate the script for compiling things with ASAN.
            final_asan_build_script = results[test_dir]['build-script']
            fuzzer_out = '/src/generated-fuzzer'
            final_asan_build_script += "\n%s %s -o %s" % (
                " ".join(cmd), build_command_includes, fuzzer_out)

            # Wrap all the parts we need for building and running the fuzzer.
            results_to_run.append({
                'build-script': final_asan_build_script,
                'source': full_fuzzer_source,
                'fuzzer-file': '/src/empty-fuzzer.cpp',
                'fuzzer-out': fuzzer_out
            })

        # Build the fuzzer for each project
        idx = 0
        print("RESULTS TO ANALYSE: %d" % (len(results_to_run)))
        for res in results_to_run:
            print("Build script:")
            print(res['build-script'])
            print("-" * 45)
            print("Source:")
            print(res['source'])
            print("-" * 45)

            with open(res['fuzzer-file'], 'w') as f:
                f.write(res['source'])
            with open('/src/build.sh', 'w') as f:
                f.write(res['build-script'])

            modified_env = os.environ
            modified_env['SANITIZER'] = 'address'
            try:

                subprocess.check_call("compile", shell=True, env=modified_env)
                build_returned_error = False
            except subprocess.CalledProcessError:
                build_returned_error = True

            if build_returned_error == False:
                shutil.copy(
                    res['fuzzer-out'],
                    os.path.basename(test_dir) + '-fuzzer-generated-%d' %
                    (idx))
                idx += 1


if __name__ == "__main__":
    setup(sys.argv[1])
