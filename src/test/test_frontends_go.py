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
"""Unit testing script for the Go frontend"""

from fuzz_introspector.frontends import oss_fuzz  # noqa: E402


def test_tree_sitter_go_sample1():
    project = oss_fuzz.analyse_folder(
        'go',
        'src/test/data/source-code/go/test-project-1',
        dump_output=False,
    )

    # Project check
    harness = project.get_source_codes_with_harnesses()
    assert len(harness) == 1

    functions_reached = project.get_reachable_functions(harness[0].source_file, harness[0])

    # Callsite check
    assert 'calculate' in functions_reached
    assert 'fmt.Sprintf' in functions_reached
    assert 'unusedFunction' not in functions_reached


def test_tree_sitter_go_sample2():
    project = oss_fuzz.analyse_folder(
        'go',
        'src/test/data/source-code/go/test-project-2',
        dump_output=False,
    )

    # Project check
    harness = project.get_source_codes_with_harnesses()
    assert len(harness) == 1

    functions_reached = project.get_reachable_functions(harness[0].source_file, harness[0])

    # Callsite check
    assert 'strconv.Atoi' in functions_reached
    assert 'Person.Greet' in functions_reached
    assert 'Dog.Greet' not in functions_reached
    assert 'Person.UnusedMethod' not in functions_reached


def test_tree_sitter_go_sample3():
    project = oss_fuzz.analyse_folder(
        'go',
        'src/test/data/source-code/go/test-project-3',
        dump_output=False,
    )

    # Project check
    harness = project.get_source_codes_with_harnesses()
    assert len(harness) == 1

    functions_reached = project.get_reachable_functions(harness[0].source_file, harness[0])

    # Callsite check
    assert 'strconv.Atoi' in functions_reached
    assert 'NewDog' in functions_reached
    assert 'Person.Greet' in functions_reached
    assert 'Dog.Introduce' in functions_reached
    assert 'Robot.Describe' in functions_reached
    assert 'Person.Introduce' not in functions_reached
    assert 'Person.Describe' not in functions_reached
    assert 'Dog.Greet' not in functions_reached
    assert 'Dog.Describe' not in functions_reached
    assert 'Robot.Greet' not in functions_reached
    assert 'Robot.Introduce' not in functions_reached


def test_tree_sitter_go_sample4():
    project = oss_fuzz.analyse_folder(
        'go',
        'src/test/data/source-code/go/test-project-4',
        dump_output=False,
    )

    # Project check
    harness = project.get_source_codes_with_harnesses()
    assert len(harness) == 1

    functions_reached = project.get_reachable_functions(harness[0].source_file, harness[0])

    # Callsite check
    assert 'strconv.Atoi' in functions_reached
    assert 'Person.Greet' in functions_reached
    assert 'Dog.Introduce' in functions_reached
    assert 'Robot.Describe' in functions_reached
    assert 'Person.Introduce' not in functions_reached
    assert 'Person.Describe' not in functions_reached
    assert 'Dog.Greet' not in functions_reached
    assert 'Dog.Describe' not in functions_reached
    assert 'Robot.Greet' not in functions_reached
    assert 'Robot.Introduce' not in functions_reached


def test_tree_sitter_go_sample5():
    """
    Similar to test_tree_sitter_rust_sample2, it is not able to
    deteremine what instance the item is used until runtime.
    """
    project = oss_fuzz.analyse_folder(
        'go',
        'src/test/data/source-code/go/test-project-5',
        dump_output=False,
    )

    # Project check
    harness = project.get_source_codes_with_harnesses()
    assert len(harness) == 1

    functions_reached = project.get_reachable_functions(harness[0].source_file, harness[0])

    # Callsite check
    assert 'strconv.ParseFloat' in functions_reached
    assert 'Shape.Area' in functions_reached
    assert 'Shape.Perimeter' in functions_reached


def test_tree_sitter_go_sample6():
    project = oss_fuzz.analyse_folder(
        'go',
        'src/test/data/source-code/go/test-project-6',
        dump_output=False,
    )

    # Project check
    harness = project.get_source_codes_with_harnesses()
    assert len(harness) == 1

    functions_reached = project.get_reachable_functions(harness[0].source_file, harness[0])

    # Callsite check
    assert 'Circle.Describe' in functions_reached
    assert 'time.Sleep' in functions_reached
    assert 'Square.Describe' not in functions_reached
    assert 'unreachableGoroutine' not in functions_reached


def test_tree_sitter_go_sample7():
    project = oss_fuzz.analyse_folder(
        'go',
        'src/test/data/source-code/go/test-project-7',
        dump_output=False,
    )

    # Project check
    harness = project.get_source_codes_with_harnesses()
    assert len(harness) == 1

    functions_reached = project.get_reachable_functions(harness[0].source_file, harness[0])

    # Callsite check
    assert 'package.SayHello' in functions_reached


def test_tree_sitter_go_sample8():
    project = oss_fuzz.analyse_folder(
        'go',
        'src/test/data/source-code/go/test-project-8',
        dump_output=False,
    )

    # Project check
    harness = project.get_source_codes_with_harnesses()
    assert len(harness) == 1

    functions_reached = project.get_reachable_functions(harness[0].source_file, harness[0])

    # Callsite check
    assert 'Person.Greet' in functions_reached
    assert 'Shape.Area' in functions_reached
    assert 'Shape.Perimeter' in functions_reached
    assert 'close' in functions_reached
    assert 'unreachableGoroutine' not in functions_reached
    assert 'processValue' not in functions_reached
    assert 'Person.GoodBye' not in functions_reached


def test_tree_sitter_go_sample9():
    project = oss_fuzz.analyse_folder(
        'go',
        'src/test/data/source-code/go/test-project-9',
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

    assert 'SharedFunctionA' in functions_reached_one
    assert 'unreachableMethodA' not in functions_reached_one
    assert 'unreachableMethodB' not in functions_reached_one
    assert 'SharedFunctionB' not in functions_reached_one

    assert 'SharedFunctionB' in functions_reached_two
    assert 'unreachableMethodA' not in functions_reached_two
    assert 'unreachableMethodB' not in functions_reached_two
    assert 'SharedFunctionA' not in functions_reached_two
