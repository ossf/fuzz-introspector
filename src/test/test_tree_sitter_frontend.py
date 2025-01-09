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
"""Unit testing script for tree-sitter-frontend."""

from fuzz_introspector.frontends import oss_fuzz  # noqa: E402


def test_tree_sitter_cpp_sample1():
    callsites = oss_fuzz.analyse_folder(
        'c++',
        'src/test/tree-sitter-frontend/cpp/test-project-1',
        'LLVMFuzzerTestOneInput',
    )

    assert len(callsites[0].split('\n')) == 6
    assert (
        '    isPositive '
        'src/test/tree-sitter-frontend/cpp/test-project-1/sample.cpp'
        in callsites[0]
    )


def test_tree_sitter_cpp_sample2():
    callsites = oss_fuzz.analyse_folder(
        'c++',
        'src/test/tree-sitter-frontend/cpp/test-project-2',
        'LLVMFuzzerTestOneInput',
    )

    assert len(callsites[0].split('\n')) == 13
    assert (
        '      RecursiveNamespace::fibonacci '
        'src/test/tree-sitter-frontend/cpp/test-project-2/recursive.cpp'
        in callsites[0]
    )
    assert (
        '    File2Namespace::functionInFile2 '
        'src/test/tree-sitter-frontend/cpp/test-project-2/crossfile.cpp'
        in callsites[0]
    )


def test_tree_sitter_cpp_sample3():
    callsites = oss_fuzz.analyse_folder(
        'c++',
        'src/test/tree-sitter-frontend/cpp/test-project-3',
        'LLVMFuzzerTestOneInput',
    )

    assert len(callsites[0].split('\n')) == 14
    assert (
        '      std::reverse '
        'src/test/tree-sitter-frontend/cpp/test-project-3/deep_chain.cpp'
        in callsites[0]
    )
    assert (
        '          DeepNamespace::level5 '
        'src/test/tree-sitter-frontend/cpp/test-project-3/deep_chain.cpp'
        in callsites[0]
    )


def test_tree_sitter_cpp_sample4():
    callsites = oss_fuzz.analyse_folder(
        'c++',
        'src/test/tree-sitter-frontend/cpp/test-project-4',
        'LLVMFuzzerTestOneInput',
    )

    assert len(callsites[0].split('\n')) == 6
    assert (
        '    Level1::Level2::Level3::Level4::DeepClass::deepMethod2 '
        'src/test/tree-sitter-frontend/cpp/test-project-4/deep_nested.cc'
        in callsites[0]
    )
