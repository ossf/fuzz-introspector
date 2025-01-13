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
"""Unit testing script for the JVM frontend"""

from fuzz_introspector.frontends import oss_fuzz  # noqa: E402


def test_tree_sitter_jvm_sample1():
    project = oss_fuzz.analyse_folder(
        'jvm',
        'src/test/data/source-code/jvm/test-project-1',
        'fuzzerTestOneInput',
        dump_output=False,
    )

    # Project check
    harness = project.get_source_codes_with_harnesses()
    assert len(harness) == 1

    functions_reached = project.get_reachable_methods(harness[0].source_file, harness[0])

    # Callsite check
    assert '[simple.SimpleClass].<init>(String)' in functions_reached
    assert '[simple.SimpleClass].simpleMethod()' in functions_reached
    assert '[simple.SimpleClass].<init>()' not in functions_reached
    assert '[simple.SimpleClass].unreachableMethod()' not in functions_reached


def test_tree_sitter_jvm_sample2():
    project = oss_fuzz.analyse_folder(
        'jvm',
        'src/test/data/source-code/jvm/test-project-2',
        'fuzzerTestOneInput',
        dump_output=False,
    )

    # Project check
    harness = project.get_source_codes_with_harnesses()
    assert len(harness) == 1

    functions_reached = project.get_reachable_methods(harness[0].source_file, harness[0])

    # Callsite check
    assert '[String].equals(String)' in functions_reached
    assert '[polymorphism.Cat].sound()' in functions_reached
    assert '[String].toUpperCase()' in functions_reached
    assert '[polymorphism.Dog].sound()' not in functions_reached
    assert '[polymorphism.CAnimal].sound()' not in functions_reached
    assert '[Math].random()' not in functions_reached


def test_tree_sitter_jvm_sample3():
    project = oss_fuzz.analyse_folder(
        'jvm',
        'src/test/data/source-code/jvm/test-project-3',
        'fuzzerTestOneInput',
        dump_output=False,
    )

    # Project check
    harness = project.get_source_codes_with_harnesses()
    assert len(harness) == 1

    functions_reached = project.get_reachable_methods(harness[0].source_file, harness[0])

    # Callsite check
    assert (
        '[nested.Fuzzer].test'
        '(com.code_intelligence.jazzer.api.FuzzedDataProvider)') in functions_reached
    assert 'System.out.println(String)' in functions_reached
    assert '[nested.NestedClass.InnerClass].innerMethod()' in functions_reached
    assert '[nested.RecursiveClass].recursiveMethod(int)' in functions_reached
    assert '[nested.NestedClass.InnerClass].unreachableInnerMethod()' not in functions_reached
    assert '[nested.RecursiveClass].unreachableRecursiveHelper(int)' not in functions_reached


def test_tree_sitter_jvm_sample4():
    project = oss_fuzz.analyse_folder(
        'jvm',
        'src/test/data/source-code/jvm/test-project-4',
        'fuzzerTestOneInput',
        dump_output=False,
    )

    # Project check
    harness = project.get_source_codes_with_harnesses()
    assert len(harness) == 1

    functions_reached = project.get_reachable_methods(harness[0].source_file, harness[0])

    # Callsite check
    assert '[crosspackage.helper.HelperClass].helperMethod()' in functions_reached
    assert 'System.out.println(String)' in functions_reached
    assert '[crosspackage.helper.HelperClass].unreachableHelperMethod()' not in functions_reached


def test_tree_sitter_jvm_sample5():
    project = oss_fuzz.analyse_folder(
        'jvm',
        'src/test/data/source-code/jvm/test-project-5',
        'fuzzerTestOneInput',
        dump_output=False,
    )

    # Project check
    harness = project.get_source_codes_with_harnesses()
    assert len(harness) == 1

    functions_reached = project.get_reachable_methods(harness[0].source_file, harness[0])

    # Callsite check
    assert '[complex.C].<init>()' in functions_reached
    assert '[complex.C].finalMethod()' in functions_reached
    assert 'System.out.println(String)' in functions_reached
    assert '[complex.A].unreachableAMethod()' not in functions_reached
    assert '[complex.B].unreachableBMethod()' not in functions_reached
    assert '[complex.C].unreachableCMethod()' not in functions_reached


def test_tree_sitter_jvm_sample6():
    """
    This test shows one of the limitation of tree-sitter approach.
    The fuzzer have the following code.
    ```
        SuperClass obj;
        if ("subclass".equals(data.consumeString(10))) {
            obj = new SubClass();
        } else {
            obj = new SuperClass();
        }
        obj.superMethod();
    ```
    In this code, the superMethod called is depending on a runtime if condition.
    It could be calling SubClass.superMethod() or SuperClass.superMethod().
    By just parsing the code, we have no way to confirm it.
    """

    project = oss_fuzz.analyse_folder(
        'jvm',
        'src/test/data/source-code/jvm/test-project-6',
        'fuzzerTestOneInput',
        dump_output=False,
    )

    # Project check
    harness = project.get_source_codes_with_harnesses()
    assert len(harness) == 1

    functions_reached = project.get_reachable_methods(harness[0].source_file, harness[0])

    # Callsite check
    assert '[inheritance.SubClass].<init>()' in functions_reached
    assert '[inheritance.SuperClass].<init>()' in functions_reached
    assert '[inheritance.SuperClass].recursiveHelper(int)' in functions_reached
    assert '[inheritance.SubClass].unreachableSubMethod()' not in functions_reached
    assert '[inheritance.SuperClass].unreachableSuperMethod()' not in functions_reached


def test_tree_sitter_jvm_sample7():
    project = oss_fuzz.analyse_folder(
        'jvm',
        'src/test/data/source-code/jvm/test-project-7',
        'fuzzerTestOneInput',
        dump_output=False,
    )

    # Project check
    harness = project.get_source_codes_with_harnesses()
    assert len(harness) == 1

    functions_reached = project.get_reachable_methods(harness[0].source_file, harness[0])

    # Callsite check
    assert '[combined.ConcreteClass].chainMethod()' in functions_reached
    assert '[combined.NestedClass.InnerClass].innerMethod()' in functions_reached
    assert '[combined.ConcreteClass].abstractMethod()' in functions_reached
    assert '[combined.AbstractBase].abstractMethod()' not in functions_reached
    assert '[combined.ConcreteClass].unreachableConcreteMethod()' not in functions_reached
    assert (
        '[combined.NestedClass.InnerClass]'
        '.unreachableInnerClassMethod()') not in functions_reached
    assert '[combined.AbstractBase].unreachableAbstractBaseMethod()' not in functions_reached


def test_tree_sitter_jvm_sample8():
    project = oss_fuzz.analyse_folder(
        'jvm',
        'src/test/data/source-code/jvm/test-project-8',
        'fuzzerTestOneInput',
        dump_output=False,
    )

    # Project check
    harness = project.get_source_codes_with_harnesses()
    assert len(harness) == 1

    functions_reached = project.get_reachable_methods(harness[0].source_file, harness[0])

    # Callsite check
    assert '[variable.B].callInstanceMethod(variable.test.A)' in functions_reached
    assert '[variable.test.A].instanceMethod()' in functions_reached
    assert 'System.out.println(String)' in functions_reached


def test_tree_sitter_jvm_sample9():
    project = oss_fuzz.analyse_folder(
        'jvm',
        'src/test/data/source-code/jvm/test-project-9',
        'fuzzerTestOneInput',
        dump_output=False,
    )

    # Project check
    harness = project.get_source_codes_with_harnesses()
    assert len(harness) == 2

    result_one = project.get_reachable_methods(harness[0].source_file, harness[0])
    result_two = project.get_reachable_methods(harness[1].source_file, harness[1])

    # Callsite check
    if 'FuzzerOne' in harness[0].source_file:
        functions_reached_one = result_one
        functions_reached_two = result_two
    else:
        functions_reached_one = result_two
        functions_reached_two = result_one

    assert '[multiple.SimpleClass].<init>(String)' in functions_reached_one
    assert '[multiple.SimpleClass].simpleMethodOne()' in functions_reached_one
    assert '[multiple.SimpleClass].<init>()' not in functions_reached_one
    assert '[multiple.SimpleClass].simpleMethodTwo()' not in functions_reached_one
    assert '[multiple.SimpleClass].unreachableMethod()' not in functions_reached_one

    assert '[multiple.SimpleClass].<init>()' in functions_reached_two
    assert '[multiple.SimpleClass].simpleMethodTwo()' in functions_reached_two
    assert '[multiple.SimpleClass].<init>(String)' not in functions_reached_two
    assert '[multiple.SimpleClass].simpleMethodOne()' not in functions_reached_two
    assert '[multiple.SimpleClass].unreachableMethod()' not in functions_reached_two
