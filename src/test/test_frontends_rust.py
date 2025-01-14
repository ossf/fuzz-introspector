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
"""Unit testing script for the Rust frontend"""

from fuzz_introspector.frontends import oss_fuzz  # noqa: E402


def test_tree_sitter_rust_sample1():
    project = oss_fuzz.analyse_folder(
        'rust',
        'src/test/data/source-code/rust/test-project-1',
        dump_output=False,
    )

    # Project check
    harness = project.get_source_codes_with_harnesses()
    assert len(harness) == 1

    functions_reached = project.get_reachable_functions(harness[0].source_file, harness[0])

    # Callsite check
    assert 'and_then' in functions_reached
    assert 'parse::<u32>' in functions_reached
    assert 'factorial' in functions_reached


def test_tree_sitter_rust_sample2():
    """
    Similar to test_tree_sitter_jvm_sample6, for macro_deinition of
    general expr type, it is not possible to determine which function
    is being called specifically as that is determine in runtime when
    the data is passed in. Thus only plain function name is meaningful
    in this situation.
    """
    project = oss_fuzz.analyse_folder(
        'rust',
        'src/test/data/source-code/rust/test-project-2',
        dump_output=False,
    )

    # Project check
    harness = project.get_source_codes_with_harnesses()
    assert len(harness) == 1

    functions_reached = project.get_reachable_functions(harness[0].source_file, harness[0])

    # Callsite check
    assert 'double_add' in functions_reached
    assert 'add' in functions_reached


def test_tree_sitter_rust_sample3():
    project = oss_fuzz.analyse_folder(
        'rust',
        'src/test/data/source-code/rust/test-project-3',
        dump_output=False,
    )

    # Project check
    harness = project.get_source_codes_with_harnesses()
    assert len(harness) == 1

    functions_reached = project.get_reachable_functions(harness[0].source_file, harness[0])

    # Callsite check
    assert 'mod_a::function_a' in functions_reached
    assert 'mod_b::function_b' in functions_reached
    assert 'is_uppercase' in functions_reached
    assert '&str::to_uppercase' in functions_reached


def test_tree_sitter_rust_sample4():
    project = oss_fuzz.analyse_folder(
        'rust',
        'src/test/data/source-code/rust/test-project-4',
        dump_output=False,
    )

    # Project check
    harness = project.get_source_codes_with_harnesses()
    assert len(harness) == 1

    functions_reached = project.get_reachable_functions(harness[0].source_file, harness[0])

    # Callsite check
    assert 'Some' in functions_reached
    assert '&[u8]::len' in functions_reached
    assert 'reachable_function' in functions_reached
    assert 'unused_function' not in functions_reached


def test_tree_sitter_rust_sample5():
    project = oss_fuzz.analyse_folder(
        'rust',
        'src/test/data/source-code/rust/test-project-5',
        dump_output=False,
    )

    # Project check
    harness = project.get_source_codes_with_harnesses()
    assert len(harness) == 1

    functions_reached = project.get_reachable_functions(harness[0].source_file, harness[0])

    # Callsite check
    assert '&str::is_empty' in functions_reached
    assert 'RecursiveStruct::new' in functions_reached
    assert 'RecursiveStruct::process' in functions_reached


def test_tree_sitter_rust_sample6():
    project = oss_fuzz.analyse_folder(
        'rust',
        'src/test/data/source-code/rust/test-project-6',
        dump_output=False,
    )

    # Project check
    harness = project.get_source_codes_with_harnesses()
    assert len(harness) == 1

    functions_reached = project.get_reachable_functions(harness[0].source_file, harness[0])

    # Callsite check
    assert 'utils::call_with' in functions_reached
    assert 'f' in functions_reached
    assert 'utils::process_str' in functions_reached
    assert '&str::is_empty' in functions_reached
    assert '&str::to_string' in functions_reached


def test_tree_sitter_rust_sample7():
    project = oss_fuzz.analyse_folder(
        'rust',
        'src/test/data/source-code/rust/test-project-7',
        dump_output=False,
    )

    # Project check
    harness = project.get_source_codes_with_harnesses()
    assert len(harness) == 1

    functions_reached = project.get_reachable_functions(harness[0].source_file, harness[0])

    # Callsite check
    assert 'poly::Derived::action' in functions_reached
    assert '&[u8]::first' in functions_reached
    assert 'Base::action' not in functions_reached
    assert 'poly::Unreached::action' not in functions_reached
    assert '&[u8]::len' not in functions_reached


def test_tree_sitter_rust_sample8():
    project = oss_fuzz.analyse_folder(
        'rust',
        'src/test/data/source-code/rust/test-project-8',
        dump_output=False,
    )

    # Project check
    harness = project.get_source_codes_with_harnesses()
    assert len(harness) == 1

    functions_reached = project.get_reachable_functions(harness[0].source_file, harness[0])

    # Callsite check
    assert '&str::to_owned' in functions_reached
    assert '&str::to_uppercase' in functions_reached
    assert 'CombinedStruct::new' in functions_reached
    assert 'CombinedStruct::complex_process' in functions_reached


def test_tree_sitter_rust_sample9():
    project = oss_fuzz.analyse_folder(
        'rust',
        'src/test/data/source-code/rust/test-project-9',
        dump_output=False,
    )

    # Project check
    harness = project.get_source_codes_with_harnesses()
    assert len(harness) == 2

    result_one = project.get_reachable_functions(harness[0].source_file, harness[0])
    result_two = project.get_reachable_functions(harness[1].source_file, harness[1])

    # Callsite check
    if 'fuzzer_one' in harness[0].source_file:
        functions_reached_one = result_one
        functions_reached_two = result_two
    else:
        functions_reached_one = result_two
        functions_reached_two = result_one

    assert 'add_one' in functions_reached_one
    assert 'multiply_by_two' not in functions_reached_one

    assert 'multiply_by_two' in functions_reached_two
    assert 'add_one' not in functions_reached_two
