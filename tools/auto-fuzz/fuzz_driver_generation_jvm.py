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
import yaml

from typing import List, Set, Any


class FuzzTarget:
    function_target: str
    function_class: str
    exceptions_to_handle: Set[str]
    fuzzer_source_code: str
    variables_to_add: List[Any]
    imports_to_add: Set[str]
    heuristics_used: List[str]

    def __init__(self):
        self.function_target = ""
        self.function_class = ""
        self.exceptions_to_handle = set()
        self.fuzzer_source_code = ""
        self.variables_to_add = []
        self.imports_to_add = set()
        self.heuristics_used = []

    def __dict__(self):
        return {"function": self.function_target}

    def to_json(self):
        return self.function_target

    def __str__(self):
        return self.function_target

    def __name__(self):
        return "function"

    def generate_patched_fuzzer(self, filename):
        """Patches the fuzzer in `filename`.
        Performs three actions:
        1) Adds the imports necessary for the fuzzer.
        2) Adds the variables that should be seeded with fuzzing data.
        3) Adds the source code of the fuzzer.
        """

        # Hold the source code of the ending fuzzer.
        content = ""

        # Open the base fuzzer and patch while reading through the file.
        with open(filename, "r") as f:
            for line in f:
                if "/*IMPORTS*/" in line:
                    # Insert Java class import statement
                    content += "".join(self.imports_to_add)
                    content += "\n// "
                    content += ",".join(self.heuristics_used)
                    content += "\n"
                elif "/*CODE*/" in line:
                    # Insert Fuzzer main code logic and replace variables
                    code = self.fuzzer_source_code.replace(
                        "$VARIABLE$", ",".join(self.variables_to_add))
                    content += code
                else:
                    # Copy other lines from the base fuzzer
                    content += line
        return content


def _determine_import_statement(classname):
    """Generate java import statement for a given class name"""
    primitives = [
        "boolean", "byte", "char", "short", "int", "long", "float", "double",
        "void"
    ]

    if classname and not classname.startswith('java.lang.'):
        classname = classname.split("$")[0].replace("[]", "")
        if classname not in primitives:
            return 'import %s;\n' % classname

    return ''


def _handle_import(func_elem):
    """Loop through the method element and retrieve all necessary import.
    The key to look for are shown in the following list.
    1. functionSourceFile
    2. returnType
    3. argTypes
    4. exceptions
    """
    import_set = set()

    # functionSourceFile
    import_set.add(_determine_import_statement(
        func_elem['functionSourceFile']))

    # returnType
    import_set.add(_determine_import_statement(func_elem['returnType']))

    # argTypes
    for argType in func_elem['argTypes']:
        import_set.add(_determine_import_statement(argType))

    # exceptions
    for exception in func_elem['JavaMethodInfo']['exceptions']:
        import_set.add(_determine_import_statement(exception))

    return list(import_set)


def _handle_argument(argType, init_dict, possible_target, recursion_count):
    """Generate data creation statement for given argument type"""
    if argType == "int" or argType == "java.lang.Integer":
        return "data.consumeInt(0,100)"
    elif argType == "int[]" or argType == "java.lang.Integer[]":
        return "data.consumeInts(100)"
    elif argType == "boolean" or argType == "java.lang.Boolean":
        return "data.consumeBoolean()"
    elif argType == "boolean[]" or argType == "java.lang.Boolean[]":
        return "data.consumeBooleans(100)"
    elif argType == "byte" or argType == "java.lang.Byte":
        return "data.consumeByte()"
    elif argType == "byte[]" or argType == "java.lang.Byte[]":
        return "data.consumeBytes(100)"
    elif argType == "short" or argType == "java.lang.Short":
        return "data.consumeShort()"
    elif argType == "short[]" or argType == "java.lang.Short[]":
        return "data.consumeShorts(100)"
    elif argType == "long" or argType == "java.lang.Long":
        return "data.consumeLong()"
    elif argType == "long[]" or argType == "java.lang.Long[]":
        return "data.consumeLongs(100)"
    elif argType == "float" or argType == "java.lang.Float":
        return "data.consumeFloat()"
    elif argType == "char" or argType == "java.lang.Character":
        return "data.consumeCharacter()"
    elif argType == "java.lang.String":
        return "data.consumeString(100)"
    else:
        return _handle_object_creation(argType, init_dict, possible_target,
                                       recursion_count)


def _search_concrete_subclass(classname, init_dict):
    """Search concrete subclass for the target classname"""
    for key in init_dict:
        func_elem = init_dict[key]
        java_info = func_elem['JavaMethodInfo']

        if not java_info[
                'superClass'] == classname and classname not in java_info[
                    'interfaces']:
            continue

        if java_info['classConcrete'] and java_info['public']:
            return func_elem
        else:
            result = _search_concrete_subclass(func_elem['functionSourceFile'],
                                               init_dict)
            if result:
                return result

    return None


def _handle_object_creation(classname, init_dict, possible_target,
                            recursion_count):
    """
    Generate statement for Java object creation of the target class.
    If constructor (<init>) does existed in the yaml file, we will
    use it as reference, otherwise the default empty constructor
    are used.
    """
    recursion_count += 1
    if init_dict and classname in init_dict.keys() and recursion_count <= 10:
        # Process arguments for constructor
        try:
            arg_list = []
            func_elem = init_dict[classname]

            if not func_elem['JavaMethodInfo']['classConcrete']:
                func_elem = _search_concrete_subclass(classname, init_dict)
            if not func_elem:
                return "new " + classname.replace("$", ".") + "()"

            classname = func_elem['functionSourceFile']
            for argType in func_elem['argTypes']:
                arg_list.append(
                    _handle_argument(argType, init_dict, possible_target,
                                     recursion_count))
            possible_target.exceptions_to_handle.update(
                func_elem['JavaMethodInfo']['exceptions'])
            possible_target.imports_to_add.update(_handle_import(func_elem))
            return "new " + classname.replace(
                "$", ".") + "(" + ",".join(arg_list) + ")"
        except RecursionError:
            # Fail to create constructor code with parameters, using default constructor
            return "new " + classname.replace("$", ".") + "()"
    else:
        return "new " + classname.replace("$", ".") + "()"


def _generate_heuristic_1(yaml_dict, possible_targets):
    """Heuristic 1.
    Creates a FuzzTarget for each method that satisfy all:
        - public class method which are not abstract or found in JDK library
        - have between 0-20 arguments
        - do not have "test" in the function name
    The fuzz target is simply one that calls into the target class function with
    suitable primitive fuzz data or simple concrete public constructor

    Will also add proper exception handling based on the exception list
    provided by the frontend code.
    """
    HEURISTIC_NAME = "jvm-autofuzz-heuristics-1"
    for func_elem in yaml_dict['All functions']['Elements']:
        java_method_info = func_elem['JavaMethodInfo']

        # Skip method which doese not match this heuristic
        if not java_method_info['static']:
            continue
        if not java_method_info['public']:
            continue
        if not java_method_info['concrete']:
            continue
        if java_method_info['javaLibraryMethod']:
            continue
        if len(func_elem['argTypes']) > 20:
            continue
        if "test" in func_elem['functionName']:
            continue

        possible_target = FuzzTarget()

        # Store target method name
        # Method name in .data.yaml for jvm: [className].methodName(methodParameterList)
        func_name = func_elem['functionName'].split('].')[1].split('(')[0]
        possible_target.function_target = func_name

        # Store function class
        func_class = func_elem['functionSourceFile'].replace('$', '.')
        possible_target.function_class = func_class

        # Store exceptions thrown by the target method
        possible_target.exceptions_to_handle.update(
            java_method_info['exceptions'])

        # Store java import statement
        possible_target.imports_to_add.update(_handle_import(func_elem))

        # Store function parameter list
        for argType in func_elem['argTypes']:
            possible_target.variables_to_add.append(
                _handle_argument(argType, None, possible_target, 0))

        # Create the actual source
        fuzzer_source_code = "  // Heuristic name: %s\n" % (HEURISTIC_NAME)
        fuzzer_source_code += "  %s.%s($VARIABLE$);\n" % (func_class,
                                                          func_name)
        if len(possible_target.exceptions_to_handle) > 0:
            fuzzer_source_code += "  try {\n" + fuzzer_source_code
            fuzzer_source_code += "  }\n"
            counter = 1
            for exc in possible_target.exceptions_to_handle:
                fuzzer_source_code += "  catch (%s e%d) {}\n" % (exc, counter)
                counter += 1
        possible_target.fuzzer_source_code = fuzzer_source_code
        possible_target.heuristics_used.append(HEURISTIC_NAME)

        possible_targets.append(possible_target)


def _generate_heuristic_2(yaml_dict, possible_targets):
    """Heuristic 2.
    Creates a FuzzTarget for each method that satisfy all:
        - public object method which are not abstract or found in JDK library
        - have between 0-20 arguments
        - do not have "test" in the function name
    The fuzz target is simply one that calls into the target function with
    a string seeded with fuzz data. It will create the object with the class
    constructor before calling the function. Primitive type will be passed
    with the seeded fuzz data.

    Will also add proper exception handling based on the exception list
    provided by the frontend code.
    """
    HEURISTIC_NAME = "jvm-autofuzz-heuristics-2"
    # Retrieve <init> method definition for all classes
    init_dict = {}
    method_list = []
    for func_elem in yaml_dict['All functions']['Elements']:
        if "<init>" in func_elem['functionName']:
            init_dict[func_elem['functionSourceFile']] = func_elem
        else:
            method_list.append(func_elem)
    print(len(method_list))
    for func_elem in method_list:
        print(func_elem['functionName'])
        java_method_info = func_elem['JavaMethodInfo']

        # Skip method which doese not match this heuristic
        if java_method_info['static']:
            continue
        if not java_method_info['public']:
            continue
        if not java_method_info['concrete']:
            continue
        if java_method_info['javaLibraryMethod']:
            continue
        if len(func_elem['argTypes']) > 20:
            continue
        if "test" in func_elem['functionName']:
            continue

        possible_target = FuzzTarget()

        # Store target method name
        # Method name in .data.yaml for jvm: [className].methodName(methodParameterList)
        func_name = func_elem['functionName'].split('].')[1].split('(')[0]
        possible_target.function_target = func_name

        # Store function class
        func_class = func_elem['functionSourceFile'].replace('$', '.')
        possible_target.function_class = func_class

        # Store exceptions thrown by the target method
        possible_target.exceptions_to_handle.update(
            java_method_info['exceptions'])

        # Store java import statement
        possible_target.imports_to_add.update(_handle_import(func_elem))

        # Store function parameter list
        for argType in func_elem['argTypes']:
            possible_target.variables_to_add.append(
                _handle_argument(argType, init_dict, possible_target, 0))

        # Create the actual source
        fuzzer_source_code = "  // Heuristic name: %s\n" % (HEURISTIC_NAME)
        fuzzer_source_code += "  %s obj = %s;\n" % (
            func_class,
            _handle_object_creation(func_class, init_dict, possible_target, 0))
        fuzzer_source_code += "  obj.%s($VARIABLE$);\n" % (func_name)
        if len(possible_target.exceptions_to_handle) > 0:
            fuzzer_source_code = "  try {\n" + fuzzer_source_code
            fuzzer_source_code += "  }\n"
            counter = 1
            for exc in possible_target.exceptions_to_handle:
                fuzzer_source_code += "  catch (%s e%d) {}\n" % (exc, counter)
                counter += 1
        possible_target.fuzzer_source_code = fuzzer_source_code
        possible_target.heuristics_used.append(HEURISTIC_NAME)

        possible_targets.append(possible_target)


def generate_possible_targets(proj_folder):
    """Generate all possible targets for a given project folder"""

    # Read the Fuzz Introspector generated data
    yaml_file = os.path.join(proj_folder, "work",
                             "fuzzerLogFile-Fuzz1.data.yaml")
    with open(yaml_file, "r") as stream:
        yaml_dict = yaml.safe_load(stream)

    possible_targets = []
    _generate_heuristic_1(yaml_dict, possible_targets)
    _generate_heuristic_2(yaml_dict, possible_targets)

    return possible_targets
