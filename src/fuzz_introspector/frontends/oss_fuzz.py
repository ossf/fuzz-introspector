# Copyright 2024 Fuzz Introspector Authors
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
#
################################################################################

import os
import pathlib
import logging

from fuzz_introspector.frontends import frontend_c
from fuzz_introspector.frontends import frontend_cpp
from fuzz_introspector.frontends import frontend_go
from fuzz_introspector.frontends import frontend_jvm
from fuzz_introspector.frontends import frontend_rust
from fuzz_introspector.frontends.datatypes import Project

from fuzz_introspector import constants

logger = logging.getLogger(name=__name__)

EXCLUDE_DIRECTORIES = [
    'node_modules', 'aflplusplus', 'honggfuzz', 'inspector', 'libfuzzer',
    'fuzztest', 'target', 'build'
]


def capture_source_files_in_tree(directory_tree: str,
                                 language: str) -> list[str]:
    """Captures source code files in a given directory."""
    language_files = []
    language_extensions = constants.LANGUAGE_EXTENSIONS.get(
        language.lower(), [])

    for dirpath, _, filenames in os.walk(directory_tree):
        # Skip some non project directories
        if any(exclude in dirpath for exclude in EXCLUDE_DIRECTORIES):
            continue

        for filename in filenames:
            if pathlib.Path(filename).suffix in language_extensions:
                language_files.append(os.path.join(dirpath, filename))
    return language_files


def process_c_project(target_dir: str,
                      entrypoint: str,
                      out: str,
                      source_files: list[str],
                      module_only: bool = False,
                      dump_output: bool = True) -> Project:
    """Process a project in C language"""
    # Default entrypoint
    if not entrypoint:
        entrypoint = 'LLVMFuzzerTestOneInput'

    logger.info('Going C route')
    logger.info('Found %d files to include in analysis', len(source_files))
    logger.info('Loading tree-sitter trees')
    source_codes = frontend_c.load_treesitter_trees(source_files)

    logger.info('Creating base project.')
    project = frontend_c.CProject(source_codes)

    # We may not need to do this, but will do it while refactoring into
    # the new frontends.
    if not project.get_source_codes_with_harnesses():
        target = os.path.join(out, 'fuzzerLogFile-0.data.yaml')
        project.dump_module_logic(target, 'no-harness-in-project', '',
                                  target_dir, dump_output)

        with open(os.path.join(out, 'fuzzerLogFile-0.data'), 'w') as f:
            f.write("Call tree\n")
            f.write("====================================")

    if module_only:
        idx = 1
        target = os.path.join(out, 'report.yaml')
        project.dump_module_logic(target, harness_source=target_dir)

    if entrypoint != 'LLVMFuzzerTestOneInput':
        calltree_source = project.get_source_code_with_target(entrypoint)
        if calltree_source:
            calltree = project.extract_calltree(source_code=calltree_source,
                                                function=entrypoint)
            with open(os.path.join(out, 'targetCalltree.txt'), 'w') as f:
                f.write("Call tree\n")
                f.write(calltree)
                f.write("====================================")
    else:
        for idx, harness in enumerate(
                project.get_source_codes_with_harnesses()):

            target = os.path.join(out, f'fuzzerLogFile-{idx}.data.yaml')
            project.dump_module_logic(target, 'LLVMFuzzerTestOneInput', '',
                                      harness.source_file, dump_output)

            logger.info('Extracting calltree for %s', harness.source_file)
            calltree = project.extract_calltree(harness, entrypoint)
            calltree = project.extract_calltree(source_code=harness,
                                                function=entrypoint)
            with open(os.path.join(out, 'fuzzerLogFile-%d.data' % (idx)),
                      'w',
                      encoding='utf-8') as f:
                f.write("Call tree\n")
                f.write(calltree)
                f.write("====================================")

    return project


def process_cpp_project(entrypoint: str,
                        out: str,
                        source_files: list[str],
                        dump_output: bool = True) -> Project:
    """Process a project in CPP language"""
    # Default entrypoint
    if not entrypoint:
        entrypoint = 'LLVMFuzzerTestOneInput'

    # Process tree sitter for c++ source files
    logger.info('Going C++ route')
    logger.info('Found %d files to include in analysis', len(source_files))
    logger.info('Loading tree-sitter trees')
    source_codes = frontend_cpp.load_treesitter_trees(source_files)

    # Create and dump project
    logger.info('Creating base project.')
    project = frontend_cpp.CppProject(source_codes)

    return project


def process_go_project(out: str,
                       source_files: list[str],
                       dump_output: bool = True) -> Project:
    """Process a project in Go language"""
    # Process tree sitter for go source files
    logger.info('Going Go route')
    logger.info('Found %d files to include in analysis', len(source_files))
    logger.info('Loading tree-sitter trees')
    source_codes = frontend_go.load_treesitter_trees(source_files)

    # Create and dump project
    logger.info('Creating base project.')
    project = frontend_go.GoProject(source_codes)

    return project


def process_jvm_project(entrypoint: str,
                        out: str,
                        source_files: list[str],
                        dump_output: bool = True) -> Project:
    """Process a project in JVM based language"""
    # Default entrypoint
    if not entrypoint:
        entrypoint = 'fuzzerTestOneInput'

    # Process tree sitter for go source files
    logger.info('Going JVM route')
    logger.info('Found %d files to include in analysis', len(source_files))
    logger.info('Loading tree-sitter trees')
    source_codes = frontend_jvm.load_treesitter_trees(source_files, entrypoint)

    # Create and dump project
    logger.info('Creating base project.')
    project = frontend_jvm.JvmProject(source_codes)

    return project


def process_rust_project(out: str,
                         source_files: list[str],
                         dump_output: bool = True) -> Project:
    """Process a project in Rust based language"""
    # Process tree sitter for rust source files
    logger.info('Going Rust route')
    logger.info('Found %d files to include in analysis', len(source_files))
    logger.info('Loading tree-sitter trees')
    source_codes = frontend_rust.load_treesitter_trees(source_files)

    # Create and dump project
    logger.info('Creating base project.')
    project = frontend_rust.RustProject(source_codes)

    return project


def analyse_folder(language: str = '',
                   directory: str = '',
                   entrypoint: str = '',
                   out='',
                   module_only=False,
                   dump_output=True) -> Project:
    """Runs a full frontend analysis on a given directory"""

    # Extract source files for target language
    source_files = capture_source_files_in_tree(directory, language)

    if language == constants.LANGUAGES.C:
        project = process_c_project(directory,
                                    entrypoint,
                                    out,
                                    source_files,
                                    module_only,
                                    dump_output=dump_output)
    else:
        # Process for different language
        if language == constants.LANGUAGES.CPP:
            project = process_cpp_project(entrypoint,
                                          out,
                                          source_files,
                                          dump_output=dump_output)
        elif language == constants.LANGUAGES.GO:
            project = process_go_project(out,
                                         source_files,
                                         dump_output=dump_output)
        elif language == constants.LANGUAGES.JAVA:
            project = process_jvm_project(entrypoint,
                                          out,
                                          source_files,
                                          dump_output=dump_output)
        elif language == constants.LANGUAGES.RUST:
            project = process_rust_project(out,
                                           source_files,
                                           dump_output=dump_output)
        else:
            logger.error('Unsupported language: %s', language)
            return Project([])

        # Process calltree and method data
        for harness in project.get_source_codes_with_harnesses():
            if language == 'go':
                entry_function = harness.get_entry_function_name()
            else:
                entry_function = entrypoint

            harness_name = harness.source_file.split('/')[-1].split('.')[0]

            # Functions/Methods data
            logger.info(f'Dump methods for {harness_name}')
            target = os.path.join(out,
                                  f'fuzzerLogFile-{harness_name}.data.yaml')
            project.dump_module_logic(target,
                                      entry_function=entry_function,
                                      harness_name=harness_name,
                                      harness_source=harness.source_file,
                                      dump_output=dump_output)

            # Calltree
            logger.info(f'Extracting calltree for {harness_name}')
            calltree = project.extract_calltree(harness.source_file, harness,
                                                entry_function)
            if dump_output:
                target = os.path.join(out,
                                      f'fuzzerLogFile-{harness_name}.data')
                with open(target, 'w', encoding='utf-8') as f:
                    f.write(f'Call tree\n{calltree}')

    return project
