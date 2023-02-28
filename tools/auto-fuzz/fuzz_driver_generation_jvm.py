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
import itertools

from typing import List, Set, Any


class FuzzTarget:
    function_target: str
    function_class: str
    exceptions_to_handle: Set[str]
    fuzzer_source_code: str
    variables_to_add: List[Any]
    imports_to_add: Set[str]
    heuristics_used: List[str]

    def __init__(self, orig=None):
        if orig:
            self.function_target = orig.function_target
            self.function_class = orig.function_class
            self.exceptions_to_handle = orig.exceptions_to_handle
            self.fuzzer_source_code = orig.fuzzer_source_code
            self.variables_to_add = orig.variables_to_add
            self.imports_to_add = orig.imports_to_add
            self.heuristics_used = orig.heuristics_used
        else:
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


def _handle_argument(argType,
                     init_dict,
                     possible_target,
                     recursion_count,
                     max_target,
                     obj_creation=True,
                     handled=[]):
    """Generate data creation statement for given argument type"""
    if argType == "int" or argType == "java.lang.Integer":
        return ["data.consumeInt(0,100)"]
    elif argType == "int[]" or argType == "java.lang.Integer[]":
        return ["data.consumeInts(100)"]
    elif argType == "boolean" or argType == "java.lang.Boolean":
        return ["data.consumeBoolean()"]
    elif argType == "boolean[]" or argType == "java.lang.Boolean[]":
        return ["data.consumeBooleans(100)"]
    elif argType == "byte" or argType == "java.lang.Byte":
        return ["data.consumeByte()"]
    elif argType == "byte[]" or argType == "java.lang.Byte[]":
        return ["data.consumeBytes(100)"]
    elif argType == "short" or argType == "java.lang.Short":
        return ["data.consumeShort()"]
    elif argType == "short[]" or argType == "java.lang.Short[]":
        return ["data.consumeShorts(100)"]
    elif argType == "long" or argType == "java.lang.Long":
        return ["data.consumeLong()"]
    elif argType == "long[]" or argType == "java.lang.Long[]":
        return ["data.consumeLongs(100)"]
    elif argType == "float" or argType == "java.lang.Float":
        return ["data.consumeFloat()"]
    elif argType == "char" or argType == "java.lang.Character":
        return ["data.consumeCharacter()"]
    elif argType == "java.lang.String":
        return ["data.consumeString(100)"]
    elif obj_creation:
        return _handle_object_creation(argType, init_dict, possible_target,
                                       recursion_count, max_target, handled)
    else:
        return []


def _search_static_factory_method(classname, static_method_list,
                                  possible_target, max_target):
    """
    Search for all factory methods of the target class that statisfy all:
        - Public
        - Concrete (not abstract or interface)
        - Argument less than 20
        - No "test" in method name
        - Return an object of the target class
        - Only primitive arguments
    """
    result_list = []
    for func_elem in static_method_list:
        java_info = func_elem['JavaMethodInfo']

        # Elimnate candidates
        if not java_info['public']:
            continue
        if not java_info['concrete']:
            continue
        if len(func_elem['argTypes']) > 20:
            continue
        if "test" in func_elem['functionName']:
            continue
        if func_elem['returnType'] != classname:
            continue

        # Retrieve primitive arguments list
        arg_list = []
        for argType in func_elem['argTypes']:
            arg_list.extend(
                _handle_argument(argType, None, None, None, max_target, False))

        # Error in some parameters
        if len(arg_list) != len(func_elem['argTypes']):
            continue

        # Handle exceptions and import
        possible_target.exceptions_to_handle.update(
            func_elem['JavaMethodInfo']['exceptions'])
        possible_target.imports_to_add.update(_handle_import(func_elem))

        # Remove [] character and argument list from function name
        # Method name in .data.yaml for jvm: [className].methodName(methodParameterList)
        call = func_elem['functionName'].split('(')[0]
        call = call.replace('[', '').replace(']', '')

        # Add parameters
        call += '(' + ','.join(arg_list) + ')'

        if call:
            result_list.append(call)

        if len(result_list) >= max_target:
            break

    return result_list


def _search_factory_method(classname, static_method_list, possible_method_list,
                           possible_target, init_dict, max_target):
    """
    Search for all factory methods of the target class that statisfy all:
        - Public
        - Concrete (not abstract or interface)
        - Argument less than 20
        - No "test" in method name
        - Return an object of the target class
    """
    result_list = []
    for func_elem in possible_method_list:
        java_info = func_elem['JavaMethodInfo']

        # Elimnate candidates
        if java_info['static']:
            continue
        if not java_info['public']:
            continue
        if not java_info['concrete']:
            continue
        if len(func_elem['argTypes']) > 20:
            continue
        if "test" in func_elem['functionName']:
            continue
        if func_elem['returnType'] != classname:
            continue

        func_name = func_elem['functionName'].split('(')[0].split('].')[1]
        func_class = func_elem['functionSourceFile']

        # Retrieve arguments list
        arg_list = []
        for argType in func_elem['argTypes']:
            arg_list.append(
                _handle_argument(argType, init_dict, possible_target, 0,
                                 max_target))

        if len(arg_list) != len(func_elem['argTypes']):
            continue

        # Create possible factory method invoking statements with constructor or static factory
        for creation in _handle_object_creation(func_class, init_dict,
                                                possible_target, 0,
                                                max_target):
            if creation and len(result_list) > max_target:
                return result_list

            call = creation + "." + func_name
            for arg_item in list(itertools.product(*arg_list)):
                call += "(" + ",".join(arg_item) + ")"
                result_list.append(call)

        for creation in _search_static_factory_method(func_class,
                                                      static_method_list,
                                                      possible_target,
                                                      max_target):
            if creation and len(result_list) > max_target:
                return result_list

            call = creation + "." + func_name
            for arg_item in list(itertools.product(*arg_list)):
                call += "(" + ",".join(arg_item) + ")"
                result_list.append(call)

        # Handle exceptions and import
        possible_target.exceptions_to_handle.update(
            func_elem['JavaMethodInfo']['exceptions'])
        possible_target.imports_to_add.update(_handle_import(func_elem))

    return result_list


def _search_concrete_subclass(classname,
                              init_dict,
                              handled=[],
                              result_list=[]):
    """Search concrete subclass for the target classname"""
    for key in init_dict:
        func_elem = init_dict[key]
        java_info = func_elem['JavaMethodInfo']

        if func_elem in handled:
            continue

        if not java_info[
                'superClass'] == classname and classname not in java_info[
                    'interfaces']:
            continue

        if java_info['classConcrete'] and java_info['public']:
            if func_elem not in result_list:
                result_list.append(func_elem)
        else:
            for result in _search_concrete_subclass(
                    func_elem['functionSourceFile'], init_dict, handled):
                if result not in result_list:
                    result_list.append(result)

    return result_list


def _handle_object_creation(classname,
                            init_dict,
                            possible_target,
                            recursion_count,
                            max_target,
                            handled=[]):
    """
    Generate statement for Java object creation of the target class.
    If constructor (<init>) does existed in the yaml file, we will
    use it as reference, otherwise the default empty constructor
    are used.
    """
    recursion_count += 1
    if init_dict and classname in init_dict.keys() and recursion_count <= 5:
        # Process arguments for constructor
        try:
            arg_list = []
            class_list = []
            func_elem = init_dict[classname]

            if func_elem['JavaMethodInfo']['classConcrete']:
                class_list.append(func_elem)
            else:
                class_list.extend(
                    _search_concrete_subclass(classname, init_dict, handled))
            if len(class_list) == 0:
                return "new " + classname.replace("$", ".") + "()"

            result_list = []
            for elem in class_list:
                elem_classname = elem['functionSourceFile']
                if elem in handled:
                    continue
                handled.append(elem)
                for argType in elem['argTypes']:
                    arg = _handle_argument(argType, init_dict, possible_target,
                                           recursion_count, max_target, True,
                                           handled)
                    if arg:
                        arg_list.append(arg)
                if len(arg_list) != len(elem['argTypes']):
                    continue
                possible_target.exceptions_to_handle.update(
                    elem['JavaMethodInfo']['exceptions'])
                possible_target.imports_to_add.update(
                    _handle_import(func_elem))
                for args_item in list(itertools.product(*arg_list)):
                    result_list.append("new " +
                                       elem_classname.replace("$", ".") + "(" +
                                       ",".join(args_item) + ")")
                    if len(result_list) > max_target:
                        return result_list
            return result_list
        except RecursionError:
            # Fail to create constructor code with parameters, using default constructor
            return ["new " + classname.replace("$", ".") + "()"]
    else:
        return ["new " + classname.replace("$", ".") + "()"]


def _generate_heuristic_1(yaml_dict, possible_targets, max_target):
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
        if len(possible_targets) > max_target:
            return

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
        if "jazzer" in func_elem[
                'functionName'] or "fuzzerTestOneInput" in func_elem[
                    'functionName']:
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
            arg_list = _handle_argument(argType, None, possible_target, 0,
                                        max_target)
            if arg_list:
                possible_target.variables_to_add.append(arg_list[0])
        if len(possible_target.variables_to_add) != len(func_elem['argTypes']):
            continue

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


def _generate_heuristic_2(yaml_dict, possible_targets, max_target):
    """Heuristic 2.
    Creates a FuzzTarget for each method that satisfy all:
        - public object method which are not abstract or found in JDK library
        - have between 0-20 arguments
        - do not have "test" in the function name
    The fuzz target is simply one that calls into the target function with
    seeded fuzz data. It will create the object with the class constructor
    before calling the function. Primitive type will be passed with the seeded
    fuzz data.

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

    for func_elem in method_list:
        if len(possible_targets) > max_target:
            return

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
        if "jazzer" in func_elem[
                'functionName'] or "fuzzerTestOneInput" in func_elem[
                    'functionName']:
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

        # Get all possible argument lists with different possible object creation combination
        for argType in func_elem['argTypes']:
            arg_list = _handle_argument(argType, init_dict, possible_target, 0,
                                        max_target)
            if arg_list:
                possible_target.variables_to_add.append(arg_list[0])
        if len(possible_target.variables_to_add) != len(func_elem['argTypes']):
            continue

        # Get all object creation statement for each possible concrete classes of the object
        object_creation_list = _handle_object_creation(func_class, init_dict,
                                                       possible_target, 0,
                                                       max_target)

        for object_creation_item in object_creation_list:
            # Create possible target for all possible object creation statement
            # Clone the base target object
            cloned_possible_target = FuzzTarget(possible_target)

            # Create the actual source
            fuzzer_source_code = "  // Heuristic name: %s\n" % (HEURISTIC_NAME)
            fuzzer_source_code += "  %s obj = %s;\n" % (func_class,
                                                        object_creation_item)
            fuzzer_source_code += "  obj.%s($VARIABLE$);\n" % (func_name)
            if len(cloned_possible_target.exceptions_to_handle) > 0:
                fuzzer_source_code = "  try {\n" + fuzzer_source_code
                fuzzer_source_code += "  }\n"
                counter = 1
                for exc in cloned_possible_target.exceptions_to_handle:
                    fuzzer_source_code += "  catch (%s e%d) {}\n" % (exc,
                                                                     counter)
                    counter += 1
            cloned_possible_target.fuzzer_source_code = fuzzer_source_code
            cloned_possible_target.heuristics_used.append(HEURISTIC_NAME)

            possible_targets.append(cloned_possible_target)


def _generate_heuristic_3(yaml_dict, possible_targets, max_target):
    """Heuristic 3.
    Creates a FuzzTarget for each method that satisfy all:
        - public object method which are not abstract or found in JDK library
        - have between 0-20 arguments
        - do not have "test" in the function name
    and Object creation method that satisfy all:
        - public static method which are not abstract
        - have less than 20 primitive arguments
        - do not have "test" in the function name
        - return an object of the needed class
    Similar to Heuristic 2, the fuzz target is simply one that calls into the
    target function with seeded fuzz data. But it create the object differently
    comparing to Heuristic 2. Instead of calling constructor, it will search
    for static method in all class with primitive parameters that return the needed
    object. This approach assume those static method are factory creator of
    the needed object which is a common way to retrieve singleton object or
    provide some hidden initialization of object after creation.

    Will also add proper exception handling based on the exception list
    provided by the frontend code.
    """
    HEURISTIC_NAME = "jvm-autofuzz-heuristics-3"

    init_dict = {}
    static_method_list = []
    method_list = []
    for func_elem in yaml_dict['All functions']['Elements']:
        if "<init>" in func_elem['functionName']:
            init_dict[func_elem['functionSourceFile']] = func_elem
        elif func_elem['JavaMethodInfo']['static']:
            static_method_list.append(func_elem)
        else:
            method_list.append(func_elem)

    for func_elem in method_list:
        if len(possible_targets) > max_target:
            return

        java_method_info = func_elem['JavaMethodInfo']

        # Skip method which doese not match this heuristic
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
        if "jazzer" in func_elem[
                'functionName'] or "fuzzerTestOneInput" in func_elem[
                    'functionName']:
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
            arg_list = _handle_argument(argType, None, possible_target, 0,
                                        max_target)
            if arg_list:
                possible_target.variables_to_add.append(arg_list[0])
        if len(possible_target.variables_to_add) != len(func_elem['argTypes']):
            continue

        # Retrieve list of factory method for the target object
        factory_method_list = _search_static_factory_method(
            func_class, static_method_list, possible_target, max_target)

        for factory_method in factory_method_list:
            # Create possible target for all possible factory method
            # Clone the base target object
            cloned_possible_target = FuzzTarget(possible_target)

            # Create the actual source
            fuzzer_source_code = "  // Heuristic name: %s\n" % (HEURISTIC_NAME)
            fuzzer_source_code += "  %s obj = %s;\n" % (func_class,
                                                        factory_method)
            fuzzer_source_code += "  obj.%s($VARIABLE$);\n" % (func_name)
            if len(cloned_possible_target.exceptions_to_handle) > 0:
                fuzzer_source_code = "  try {\n" + fuzzer_source_code
                fuzzer_source_code += "  }\n"
                counter = 1
                for exc in cloned_possible_target.exceptions_to_handle:
                    fuzzer_source_code += "  catch (%s e%d) {}\n" % (exc,
                                                                     counter)
                    counter += 1
            cloned_possible_target.fuzzer_source_code = fuzzer_source_code
            cloned_possible_target.heuristics_used.append(HEURISTIC_NAME)

            possible_targets.append(cloned_possible_target)


def _generate_heuristic_4(yaml_dict, possible_targets, max_target):
    """Heuristic 4.
    Creates a FuzzTarget for each method that satisfy all:
        - public object method which are not abstract or found in JDK library
        - have between 0-20 arguments
        - do not have "test" in the function name
    and Object creation method that satisfy all:
        - public non-static method which are not abstract
        - have less than 20 arguments
        - do not have "test" in the function name
        - return an object of the needed class
    Similar to Heuristic 3, instead of static factory method, it will find
    non-static factory method instead.

    Will also add proper exception handling based on the exception list
    provided by the frontend code.
    """
    HEURISTIC_NAME = "jvm-autofuzz-heuristics-4"

    init_dict = {}
    method_list = []
    instance_method_list = []
    static_method_list = []
    for func_elem in yaml_dict['All functions']['Elements']:
        if "<init>" in func_elem['functionName']:
            init_dict[func_elem['functionSourceFile']] = func_elem
        elif func_elem['JavaMethodInfo']['static']:
            static_method_list.append(func_elem)
        else:
            instance_method_list.append(func_elem)
            method_list.append(func_elem)

    for func_elem in method_list:
        if len(possible_targets) > max_target:
            return

        java_method_info = func_elem['JavaMethodInfo']

        # Skip method which doese not match this heuristic
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
        if "jazzer" in func_elem[
                'functionName'] or "fuzzerTestOneInput" in func_elem[
                    'functionName']:
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
            arg_list = _handle_argument(argType, None, possible_target, 0,
                                        max_target)
            if arg_list:
                possible_target.variables_to_add.append(arg_list[0])
        if len(possible_target.variables_to_add) != len(func_elem['argTypes']):
            continue

        # Retrieve list of factory method for the target object
        factory_method_list = _search_factory_method(func_class,
                                                     static_method_list,
                                                     instance_method_list,
                                                     possible_target,
                                                     init_dict, max_target)

        for factory_method in factory_method_list:
            # Create possible target for all possible factory method
            # Clone the base target object
            cloned_possible_target = FuzzTarget(possible_target)

            # Create the actual source
            fuzzer_source_code = "  // Heuristic name: %s\n" % (HEURISTIC_NAME)
            fuzzer_source_code += "  %s obj = %s;\n" % (func_class,
                                                        factory_method)
            fuzzer_source_code += "  obj.%s($VARIABLE$);\n" % (func_name)
            if len(cloned_possible_target.exceptions_to_handle) > 0:
                fuzzer_source_code = "  try {\n" + fuzzer_source_code
                fuzzer_source_code += "  }\n"
                counter = 1
                for exc in cloned_possible_target.exceptions_to_handle:
                    fuzzer_source_code += "  catch (%s e%d) {}\n" % (exc,
                                                                     counter)
                    counter += 1
            cloned_possible_target.fuzzer_source_code = fuzzer_source_code
            if HEURISTIC_NAME not in cloned_possible_target.heuristics_used:
                cloned_possible_target.heuristics_used.append(HEURISTIC_NAME)

            possible_targets.append(cloned_possible_target)


def generate_possible_targets(proj_folder, max_target):
    """Generate all possible targets for a given project folder"""

    # Read the Fuzz Introspector generated data
    yaml_file = os.path.join(proj_folder, "work",
                             "fuzzerLogFile-Fuzz1.data.yaml")
    with open(yaml_file, "r") as stream:
        yaml_dict = yaml.safe_load(stream)

    possible_targets = []
    _generate_heuristic_1(yaml_dict, possible_targets, max_target)
    _generate_heuristic_2(yaml_dict, possible_targets, max_target)
    _generate_heuristic_3(yaml_dict, possible_targets, max_target)
    _generate_heuristic_4(yaml_dict, possible_targets, max_target)

    return possible_targets
