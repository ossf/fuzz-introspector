# Copyright 2025 Fuzz Introspector Authors
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
"""Unit testing script for the CPP frontend"""

import os
from fuzz_introspector.frontends import oss_fuzz  # noqa: E402


def test_tree_sitter_cpp_sample1():
    project = oss_fuzz.analyse_folder(
        'c++',
        'src/test/data/source-code/cpp/test-project-1',
        'LLVMFuzzerTestOneInput',
        dump_output=False,
    )

    # Project check
    assert len(project.get_source_codes_with_harnesses()) == 1

    functions_reached = project.get_reachable_functions(
        source_code=None,
        function='LLVMFuzzerTestOneInput',
        visited_functions=set())

    # Callsite check
    assert 'isPositive' in functions_reached


def test_tree_sitter_cpp_sample2():
    project = oss_fuzz.analyse_folder(
        'c++',
        'src/test/data/source-code/cpp/test-project-2',
        'LLVMFuzzerTestOneInput',
        dump_output=False,
    )

    # Project check
    assert len(project.get_source_codes_with_harnesses()) == 1

    functions_reached = project.get_reachable_functions(
        source_code=None,
        function='LLVMFuzzerTestOneInput',
        visited_functions=set())

    # Callsite check
    assert 'RecursiveNamespace::fibonacci' in functions_reached
    assert 'File2Namespace::functionInFile2' in functions_reached


def test_tree_sitter_cpp_sample3():
    project = oss_fuzz.analyse_folder(
        'c++',
        'src/test/data/source-code/cpp/test-project-3',
        'LLVMFuzzerTestOneInput',
        dump_output=False,
    )

    # Project check
    assert len(project.get_source_codes_with_harnesses()) == 1

    functions_reached = project.get_reachable_functions(
        source_code=None,
        function='LLVMFuzzerTestOneInput',
        visited_functions=set())

    # Callsite check
    assert 'std::reverse' in functions_reached
    assert 'DeepNamespace::level5' in functions_reached


def test_tree_sitter_cpp_sample4():
    project = oss_fuzz.analyse_folder(
        'c++',
        'src/test/data/source-code/cpp/test-project-4',
        'LLVMFuzzerTestOneInput',
        dump_output=False,
    )

    # Project check
    assert len(project.get_source_codes_with_harnesses()) == 1

    functions_reached = project.get_reachable_functions(
        source_code=None,
        function='LLVMFuzzerTestOneInput',
        visited_functions=set())

    # Callsite check
    assert 'Level1::Level2::Level3::Level4::DeepClass::deepMethod2' in functions_reached
    assert 'printf' in functions_reached
    assert 'atoi' in functions_reached


def test_tree_sitter_cpp_sample5():
    project = oss_fuzz.analyse_folder(
        'c++',
        'src/test/data/source-code/cpp/test-project-5',
        'LLVMFuzzerTestOneInput',
        dump_output=False,
    )

    # Project check
    assert len(project.get_source_codes_with_harnesses()) == 1

    functions_reached = project.get_reachable_functions(
        source_code=None,
        function='LLVMFuzzerTestOneInput',
        visited_functions=set())

    # Callsite check
    assert 'ClassOne::processInput' in functions_reached
    assert 'NamespaceOne::processInput' in functions_reached


def test_tree_sitter_cpp_sample6():
    project = oss_fuzz.analyse_folder(
        'c++',
        'src/test/data/source-code/cpp/test-project-6',
        'LLVMFuzzerTestOneInput',
        dump_output=False,
    )

    # Project check
    assert len(project.get_source_codes_with_harnesses()) == 1

    functions_reached = project.get_reachable_functions(
        source_code=None,
        function='LLVMFuzzerTestOneInput',
        visited_functions=set())

    # Callsite check
    assert 'atoi' in functions_reached


def test_tree_sitter_cpp_sample7():
    project = oss_fuzz.analyse_folder(
        'c++',
        'src/test/data/source-code/cpp/test-project-7',
        'LLVMFuzzerTestOneInput',
        dump_output=False,
    )

    # Project check
    assert len(project.get_source_codes_with_harnesses()) == 2
    project.dump_module_logic('', dump_output=False)

    calltrees = dict()
    for harness in project.get_source_codes_with_harnesses():
        calltree = project.extract_calltree(harness.source_file, harness,
                                            'LLVMFuzzerTestOneInput')
        calltrees[os.path.basename(harness.source_file)] = calltree

    assert 'func2' in calltrees['sample2.cpp'] and 'func1' not in calltrees[
        'sample2.cpp']
    assert 'func1' in calltrees['sample1.cpp'] and 'func2' not in calltrees[
        'sample1.cpp']
