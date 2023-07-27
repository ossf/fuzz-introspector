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
import constants
import itertools

from typing import List, Set, Any


class FuzzTarget:
    function_name: str
    function_target: str
    function_class: str
    exceptions_to_handle: Set[str]
    fuzzer_source_code: str
    variables_to_add: List[Any]
    imports_to_add: Set[str]
    heuristics_used: List[str]
    class_field_list: List[str]
    private_field_source_code: str
    fuzzer_file_prepare_source_code: str
    fuzzer_init_source_code: str
    fuzzer_tear_down_source_code: str

    def __init__(self, orig=None, func_elem=None):
        self.function_name = ""
        self.function_target = ""
        self.function_class = ""
        self.exceptions_to_handle = set()
        self.fuzzer_source_code = ""
        self.variables_to_add = []
        self.imports_to_add = set()
        self.heuristics_used = []
        self.class_field_list = []
        self.private_field_source_code = ""
        self.fuzzer_file_prepare_source_code = ""
        self.fuzzer_init_source_code = ""
        self.fuzzer_tear_down_source_code = ""
        if orig:
            self.function_name = orig.function_name
            self.function_target = orig.function_target
            self.function_class = orig.function_class
            self.exceptions_to_handle.update(orig.exceptions_to_handle)
            self.fuzzer_source_code = orig.fuzzer_source_code
            self.variables_to_add.extend(orig.variables_to_add)
            self.imports_to_add.update(orig.imports_to_add)
            self.heuristics_used.extend(list(set(orig.heuristics_used)))
            self.class_field_list.extend(orig.class_field_list)
            self.private_field_source_code = orig.private_field_source_code
            self.fuzzer_file_prepare_source_code = orig.fuzzer_file_prepare_source_code
            self.fuzzer_init_source_code = orig.fuzzer_init_source_code
            self.fuzzer_tear_down_source_code = orig.fuzzer_tear_down_source_code
        elif func_elem:
            # Method name in .data.yaml for jvm: [className].methodName(methodParameterList)
            self.function_name = func_elem['functionName'].split(
                '].')[1].split('(')[0]
            self.function_target = get_target_method_statement(func_elem)
            self.function_class = func_elem['functionSourceFile'].replace(
                '$', '.')
            self.exceptions_to_handle.update(
                func_elem['JavaMethodInfo']['exceptions'])
            self.imports_to_add.update(_handle_import(func_elem))

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
        4) If there are class object list for random choice, create them.
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
                elif "/*STATIC_OBJECT_CHOICE*/" in line:
                    # Create an array of possible static objects for random choice
                    for item in self.class_field_list:
                        content += item
                elif "/*PRIVATE_FIELD*/" in line:
                    # Insert fuzzer class field
                    content += private_field_source_code
                elif "/*FUZZER_INITIALIZE*/" in line:
                    # Insert fuzzer initialize code
                    content += fuzzer_init_source_code
                elif "/*FUZZER_TEAR_DOWN*/" in line:
                    # Insert fuzzer tear down code
                    content += fuzzer_tear_down_source_code
                elif "/*FILE_PREPERATION*/" in line:
                    # Insert file preparation code
                    content += self.fuzzer_file_prepare_source_code
                else:
                    # Copy other lines from the base fuzzer
                    content += line
        return content


def _is_enum_class(init_dict, classname):
    """Check if the method's class is an enum type"""
    if init_dict and classname in init_dict.keys():
        for func_elem in init_dict[classname]:
            if func_elem['JavaMethodInfo']['classEnum']:
                return True

    return False


def _is_project_class(classname):
    """Check if the method's class is in the target project"""
    global project_class_list
    if project_class_list:
        for project_class in project_class_list:
            if project_class.endswith(classname):
                return True

    return False


def _is_primitive_class(classname):
    """Determine if the classname is a java primitives"""
    primitives = [
        "boolean", "byte", "char", "short", "int", "long", "float", "double",
        "boolean[]", "byte[]", "char[]", "short[]", "int[]", "long[]",
        "float[]", "double[]", "void"
    ]

    return classname in primitives


def _is_factory_method(methodname, classname):
    """Determine if the target method is a possible factory method"""

    possible_factory_method = [
        "from", "of", "valueOf", "*instance", "create", "*Type"
    ]
    possible_factory_class = ["*builder", "*factory"]

    is_factory = False

    for method in possible_factory_method:
        if methodname.lower().endswith(method.replace("*", "")):
            is_factory = True
    for cl in possible_factory_class:
        if classname.lower().endswith(cl.replace("*", "")):
            is_factory = True

    return is_factory


def _is_method_excluded(func_elem):
    """
    Determine if the methods should be ignored for fuzzer generation.
    If any of the switch has been set to False in the constant.py, that
    specific group will not be checked and always return false.
    This method takes the method function element and returns a
    tuple of five booleans, representing if the provided method is
    being ignored by one of the five groups. The five groups are
    getter and setters, plain methods, test methods
    and methods in the Object class.
    """
    getter_setter = False
    plain = False
    test = False
    object = False

    func_name = func_elem['functionName'].split("].")[1]

    if constants.JAVA_IGNORE_GETTER_SETTER:
        if func_name.startswith("set") and len(func_elem['argTypes']) == 1:
            getter_setter = True
        if func_name.startswith("get") and len(func_elem['argTypes']) == 0:
            getter_setter = True
        if func_name.startswith("is") and len(func_elem['argTypes']) == 0:
            getter_setter = True
    if constants.JAVA_IGNORE_PLAIN_METHOD:
        if len(func_elem['argTypes']) == 0:
            plain = True
    if constants.JAVA_IGNORE_TEST_METHOD:
        if "test" in func_elem['functionName'].lower():
            test = True
        if "demo" in func_elem['functionName'].lower():
            test = True
        if "test" in func_elem['functionSourceFile'].lower():
            test = True
        if "demo" in func_elem['functionSourceFile'].lower():
            test = True
        if "jazzer" in func_elem[
                'functionName'] or "fuzzerTestOneInput" in func_elem[
                    'functionName']:
            test = True
    if constants.JAVA_IGNORE_OBJECT_METHOD:
        object_methods = [
            'clone()', 'equals(java.lang.Object)', 'finalize()', 'getClass()',
            'hashCode()', 'notify()', 'notifyAll()', 'toString()', 'wait()',
            'wait(long)', 'wait(long,int)'
        ]
        for object_method in object_methods:
            if object_method in func_elem['functionName']:
                object = True

    return getter_setter, plain, test, object


def get_target_method_statement(func_elem):
    name = func_elem['functionName'].split('].')[1]
    class_name = func_elem['functionSourceFile'].replace('$', '.')
    if func_elem['JavaMethodInfo']['static']:
        static = "static "
    else:
        static = ""

    name = "[%s] public %s%s %s" % (class_name, static,
                                    func_elem['returnType'], name)

    exception_set = set(func_elem['JavaMethodInfo']['exceptions'])
    if len(exception_set) > 0:
        name += " throws %s" % (",".join(exception_set))

    return name


def _determine_import_statement(classname):
    """Generate java import statement for a given class name"""
    if classname and not classname.startswith('java.lang.'):
        classname = classname.split("$")[0].replace("[]", "")
        if not _is_primitive_class(classname):
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
        import_set.add(_determine_import_statement(argType.split('$')[0]))

    # exceptions
    for exception in func_elem['JavaMethodInfo']['exceptions']:
        import_set.add(_determine_import_statement(exception))

    return list(import_set)


def _handle_argument(argType,
                     init_dict,
                     possible_target,
                     max_target,
                     handled,
                     obj_creation=True,
                     enum_object=False,
                     class_field=False,
                     class_object=False):
    """Generate data creation statement for given argument type"""
    if argType == "int" or argType == "java.lang.Integer":
        return ["data.consumeInt(0,100)"]
    elif argType == "int[]":
        return ["data.consumeInts(5)"]
    elif argType == "java.lang.Integer[]":
        return ["ArrayUtils.toObject(data.consumeInts(5))"]
    elif argType == "boolean" or argType == "java.lang.Boolean":
        return ["data.consumeBoolean()"]
    elif argType == "boolean[]":
        return ["data.consumeBooleans(5)"]
    elif argType == "java.lang.Boolean[]":
        return ["ArrayUtils.toObject(data.consumeBooleans(5))"]
    elif argType == "byte" or argType == "java.lang.Byte":
        return ["data.consumeByte()"]
    elif argType == "byte[]":
        return ["data.consumeBytes(5)"]
    elif argType == "java.lang.Byte[]":
        return ["ArrayUtils.toObject(data.consumeBytes(5))"]
    elif argType == "short" or argType == "java.lang.Short":
        return ["data.consumeShort()"]
    elif argType == "short[]":
        return ["data.consumeShorts(5)"]
    elif argType == "java.lang.Short[]":
        return ["ArrayUtils.toObject(data.consumeShorts(5))"]
    elif argType == "long" or argType == "java.lang.Long":
        return ["data.consumeLong()"]
    elif argType == "long[]":
        return ["data.consumeLongs(5)"]
    elif argType == "java.lang.Long[]":
        return ["ArrayUtils.toObject(data.consumeLongs(5))"]
    elif argType == "float" or argType == "java.lang.Float":
        return ["data.consumeFloat()"]
    elif argType == "char" or argType == "java.lang.Character":
        return ["data.consumeCharNoSurrogates()"]
    elif argType == "java.lang.String":
        return ["data.consumeString(100)"]
    elif argType == "java.lang.String[]":
        return ["new java.lang.String[]{data.consumeString(100)}"]

    if argType == "java.io.File":
        result = _handle_file_object(possible_target, False)
        if result:
            return result
    if argType == "java.nio.file.Path":
        result = _handle_file_object(possible_target, True)
        if result:
            return result

    if enum_object and _is_enum_class(init_dict, argType):
        result = _handle_enum_choice(init_dict, argType)
        if result:
            return result

    if class_object and argType == "java.lang.Class":
        result = _handle_class_object(init_dict)
        if result:
            return result

    if obj_creation:
        return _handle_object_creation(argType, init_dict, possible_target,
                                       max_target, handled, class_field,
                                       class_object)
    else:
        return []


def _search_static_factory_method(classname,
                                  static_method_list,
                                  possible_target,
                                  max_target,
                                  class_object=False):
    """
    Search for all factory methods of the target class that statisfy all:
        - Public
        - Concrete (not abstract or interface)
        - Argument less than 20
        - No "test" in method name
        - Return an object of the target class
        - Only primitive arguments or class object if class_object set to True
        - method name matches either one of the following
          "from" / "of" / "valueOf" / "*instance" /
          "create" / "*type"
          or methods belongs to class name matches either
          one of the following
          "*builder" / "*factory"
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

        func_name = func_elem['functionName'].split('(')[0].split('].')[1]
        func_class = func_elem['functionSourceFile'].replace('$', '.')

        if not _is_factory_method(func_name, func_class):
            continue

        # Retrieve primitive arguments list
        arg_list = []
        for argType in func_elem['argTypes']:
            arg_list.extend(
                _handle_argument(argType.replace('$', '.'),
                                 None,
                                 None,
                                 max_target, [],
                                 False,
                                 class_object=class_object))

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


def _search_factory_method(classname,
                           static_method_list,
                           possible_method_list,
                           possible_target,
                           init_dict,
                           max_target,
                           class_field=False,
                           class_object=False):
    """
    Search for all factory methods of the target class that statisfy all:
        - Public
        - Concrete (not abstract or interface)
        - Argument less than 20
        - No "test" in method name
        - Return an object of the target class
        - method name matches either one of the following
          "from" / "of" / "valueOf" / "*instance" /
          "create" / "*type"
          or methods belongs to class name matches either
          one of the following
          "*builder" / "*factory"
    """
    global need_param_combination
    result_list = []
    for func_elem in possible_method_list:
        java_info = func_elem['JavaMethodInfo']

        # Eliminate candidates
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
        func_class = func_elem['functionSourceFile'].replace('$', '.')

        if not _is_factory_method(func_name, func_class):
            continue

        # Retrieve arguments list
        arg_list = []
        for argType in func_elem['argTypes']:
            arg_list.append(
                _handle_argument(argType.replace('$', '.'), init_dict,
                                 possible_target, max_target, []))

        if len(arg_list) != len(func_elem['argTypes']):
            continue

        # Create possible factory method invoking statements with constructor or static factory
        for creation in _handle_object_creation(func_class,
                                                init_dict,
                                                possible_target,
                                                max_target, [],
                                                class_field=class_field,
                                                class_object=class_object):
            if creation and len(result_list) > max_target:
                return result_list

            call = creation + "." + func_name
            for arg_item in list(itertools.product(*arg_list)):
                call += "(" + ",".join(arg_item) + ")"
                result_list.append(call)
                if not need_param_combination:
                    break

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
                if not need_param_combination:
                    break

        # Handle exceptions and import
        possible_target.exceptions_to_handle.update(
            func_elem['JavaMethodInfo']['exceptions'])
        possible_target.imports_to_add.update(_handle_import(func_elem))

    return result_list


def _search_setting_method(method_list, target_class_name, target_method_name,
                           possible_target, max_target):
    """
    Search for all possible non-static setting methods for the target method.
    Assume all setting methods are methods belongs to the same class of the
    target method with no return value or have a name start with set (i.e. setXXX).
    """
    result_list = []
    for func_elem in method_list:
        func_name = func_elem['functionName'].split('(')[0].split('].')[1]
        func_class = func_elem['functionSourceFile'].replace('$', '.')
        if func_class != target_class_name:
            continue
        if func_name == target_method_name:
            continue
        if not func_name.startswith(
                'set') and func_elem['returnType'] != 'void':
            continue

        arg_list = []
        for argType in func_elem['argTypes']:
            arg = _handle_argument(argType.replace('$', '.'), None,
                                   possible_target, max_target, [])
            if arg:
                arg_list.append(arg[0])
        if len(arg_list) != len(func_elem['argTypes']):
            continue

        result_list.append('obj.' + func_name + '(' + ','.join(arg_list) + ')')

    return result_list


def _search_concrete_subclass(classname, init_dict, handled, result_list=[]):
    """Search concrete subclass for the target classname"""
    if init_dict and classname in init_dict.keys():
        for func_elem in init_dict[classname]:
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
                        func_elem['functionSourceFile'].replace('$', '.'),
                        init_dict, handled):
                    if result not in result_list:
                        result_list.append(result)

    return result_list


def _search_all_callsite_dst(method_list):
    """
    Search and retrieve a unique list of
    methods called by any method in the
    provided method list.
    """
    result_map = dict()
    for func_elem in method_list:
        for callsite in func_elem['Callsites']:
            if callsite['Dst'] != func_elem['functionName']:
                if callsite['Dst'] in result_map:
                    caller_list = result_map[callsite['Dst']]
                else:
                    caller_list = []
                caller_list.append(func_elem['functionName'])
                result_map[callsite['Dst']] = list(set(caller_list))

    return result_map


def _sort_method_list_key(elem):
    """
    Provide the key for sorting the method list
    """
    return elem['functionDepth']


def _should_filter_method(callsites, target_method, current_method, handled):
    """
    Search recursively if the target_method has
    been called by any methods except for themself.
    If yes, that method should be filtered.
    """
    result = True
    if current_method in callsites:
        callers = callsites[current_method]
        for caller in callers:
            if caller == target_method:
                result = False
                continue
            if caller not in callsites:
                return True
            if caller not in handled:
                if caller in callsites:
                    handled.append(caller)
                    inner_result = _should_filter_method(
                        callsites, target_method, caller, handled)
                    if inner_result:
                        return True
                    result = False
    else:
        return False

    return result


def _handle_file_object(possible_target, is_path):
    """
    Prepare a random file for any parameters
    needing a file or file path to process.
    """
    possible_target.imports_to_add.add("import java.io.File;")
    possible_target.imports_to_add.add("import java.io.FileWriter;")
    possible_target.imports_to_add.add("import java.io.IOException;")
    possible_target.imports_to_add.add("import java.io.PrintWriter;")
    possible_target.imports_to_add.add("import java.nio.file.Files;")

    possible_target.private_field_source_code = """  private static File tempDirectory;
  private static File tempFile;"""

    possible_target.fuzzer_init_source_code = """  try {
      tempDirectory = Files.createTempDirectory("oss-fuzz").toFile().getAbsoluteFile();
      tempFile = new File(tempDirectory, "oss-fuzz-temp").getAbsoluteFile();
    } catch (IOException e) {
      // Known exception
    }"""

    possible_target.fuzzer_tear_down_source_code = """  tempFile.delete();
    tempDirectory.delete();"""

    possible_target.fuzzer_file_prepare_source_code = """  try {
      PrintWriter printWriter = new PrintWriter(new FileWriter(tempFile));
      printWriter.print(data.consumeString(data.remainingBytes() / 2));
      printWriter.close();
    } catch (IOException e) {}"""

    if is_path:
        return ["tempFile.toPath()"]
    else:
        return ["tempfile"]


def _handle_enum_choice(init_dict, enum_name):
    """
    Create an array of all values of this enum
    and randomly choose one with the jazzer
    fuzzer data provider.
    """
    # Double check if the enum_name is really an enum object
    if _is_enum_class(init_dict, enum_name):
        result = enum_name + ".values()"
        result = "data.pickValue(" + result + ");\n"
        return [result]
    return []


def _handle_class_object(init_dict):
    """
    Return a list of all class object of the
    existing classes.
    """
    excluded_prefix = [
        "jdk.", "java.", "javax.", "sun.", "sunw.", "com.sun.", "com.ibm.",
        "com.apple.", "apple.awt.", "com.code_intelligence.jazzer."
    ]

    result_list = []
    if init_dict:
        for key in init_dict.keys():
            if not init_dict[key]:
                continue

            func_elem = init_dict[key][0]

            excluded = False
            for prefix in excluded_prefix:
                if func_elem['functionSourceFile'].startswith(prefix):
                    excluded = True

            if not excluded:
                classname = func_elem['functionSourceFile'].replace('$', '.')
                result_list.append(classname + '.class')

    return result_list


def _handle_class_field_list(func_elem, possible_target):
    """
    Create an array of all public static final class object
    from the given class elements to object preconfigured
    or default object
    """
    result = None
    field_list = []
    classname = func_elem['functionSourceFile'].replace('$', '.')
    for item in func_elem['JavaMethodInfo']['classFields']:
        # Check if the function element match the requirement
        if not item['static']:
            continue
        if not item['public']:
            continue
        if not item['final']:
            continue
        if not item['concrete']:
            continue

        # Filter out class field with non-match type
        field_type = item['Type'].replace('$', '.')
        if field_type != classname:
            continue

        # Store possible public static final class object name
        field_list.append(item['Name'])

    if field_list:
        class_field_array = 'final static ' + classname + '[] '
        class_field_array += classname.replace('.', '') + '={'
        for field_name in field_list:
            class_field_array += classname + '.' + field_name + ','
        class_field_array += '};'

        possible_target.class_field_list.append(class_field_array)
        result = 'data.pickValue(' + classname.replace('.', '') + ')'

    return result


def _handle_object_creation(classname,
                            init_dict,
                            possible_target,
                            max_target,
                            handled,
                            class_field=False,
                            class_object=False):
    """
    Generate statement for Java object creation of the target class.
    If constructor (<init>) does existed in the yaml file, we will
    use it as reference, otherwise the default empty constructor
    are used.
    """
    global need_param_combination

    # Handles array
    if "[]" in classname and not _is_primitive_class(classname):
        classname = classname.replace("[]", "")
        isArray = True
    else:
        isArray = False

    if init_dict and classname in init_dict.keys():
        if class_field and init_dict[classname]:
            # Use defined class object
            func_elem = init_dict[classname][0]
            class_field_choice = _handle_class_field_list(
                func_elem, possible_target)
            if class_field_choice:
                return [class_field_choice]

        result_list = []
        for func_elem in init_dict[classname]:
            # Use constructor or factory method
            try:
                arg_list = []
                class_list = []

                concrete = False
                if func_elem['JavaMethodInfo']['classConcrete']:
                    class_list.append(func_elem)
                    concrete = True
                if not concrete or constants.SEARCH_SUBCLASS_FOR_OBJECT_CREATION:
                    class_list.extend(
                        _search_concrete_subclass(classname, init_dict,
                                                  handled))
                if len(class_list) == 0:
                    return []

                for elem in class_list:
                    elem_classname = elem['functionSourceFile'].replace(
                        '$', '.')
                    if elem in handled:
                        continue
                    handled.append(elem)
                    for argType in elem['argTypes']:
                        arg = _handle_argument(argType.replace('$', '.'),
                                               init_dict,
                                               possible_target,
                                               max_target,
                                               handled,
                                               True,
                                               class_object=class_object)
                        if arg:
                            arg_list.append(arg)
                    if len(arg_list) != len(elem['argTypes']):
                        continue
                    possible_target.exceptions_to_handle.update(
                        elem['JavaMethodInfo']['exceptions'])
                    possible_target.imports_to_add.update(
                        _handle_import(func_elem))
                    for args_item in list(itertools.product(*arg_list)):
                        statement = "new " + elem_classname.replace("$", ".")
                        statement += "(" + ",".join(args_item) + ")"
                        if isArray:
                            statement = "new " + elem_classname.replace(
                                "$", ".") + "[]{%s}" % statement
                        result_list.append(statement)
                        if len(result_list) > max_target:
                            return result_list
                        if not need_param_combination:
                            break
            except RecursionError:
                # Fail to create constructor code with parameters
                pass
        return result_list
    else:
        return []


def _filter_polymorphism(method_list):
    """Filter polymorphism methods in each class. If multiple methods have the same
    name and return type, keeping the one with the most arguments. If two or more
    of them have the same number of arguments, only keeping the first one."""
    process_map = {}
    result_list = []

    # Group polymorphism method
    for func_elem in method_list:
        key = func_elem['returnType'] + func_elem['functionName'].split("(")[0]
        if key in process_map.keys():
            elem_list = process_map[key]
        else:
            elem_list = []
        elem_list.append(func_elem)
        process_map[key] = elem_list

    # Handle polymorphism method with same name and the most number of arguments
    for keys in process_map:
        target = None
        elem_list = process_map[keys]
        for func_elem in elem_list:
            if not target or len(func_elem['argTypes']) > len(
                    target['argTypes']):
                target = func_elem
        if target:
            result_list.append(target)

    return result_list


def _filter_method_list(callsites, max_count, target_method_list,
                        calldepth_filter):
    """
    Filter methods from the target_method list which has
    been called by any other methods.
    Also sort the target method list by depth call descendingly
    and only keep the top number of methods configured by the max_count.
    """
    result_method_list = []

    if calldepth_filter:
        target_method_list.sort(key=_sort_method_list_key, reverse=True)
        method_range = min(len(target_method_list), max_count)
    else:
        method_range = len(target_method_list)

    for counter in range(method_range):
        func_elem = target_method_list[counter]
        if func_elem[
                'functionName'] not in callsites or not _should_filter_method(
                    callsites, func_elem['functionName'],
                    func_elem['functionName'], []):
            result_method_list.append(func_elem)

    return result_method_list


def _filter_method(method_list, static_method_list, max_count,
                   calldepth_filter):
    """
    Filter methods from the two method list
    """
    filtered_method_list = _filter_polymorphism(method_list)

    callsites = _search_all_callsite_dst(static_method_list)
    target_callsites = _search_all_callsite_dst(filtered_method_list)
    for item in target_callsites:
        if item in callsites:
            caller_list = callsites[item]
            caller_list.extend(target_callsites[item])
            callsites[item] = list(set(caller_list))
        else:
            callsites[item] = target_callsites[item]

    filtered_method_list = _filter_method_list(callsites, max_count,
                                               filtered_method_list,
                                               calldepth_filter)
    filtered_static_method_list = _filter_method_list(callsites, max_count,
                                                      static_method_list,
                                                      calldepth_filter)

    return filtered_method_list, filtered_static_method_list


def _extract_method(yaml_dict,
                    max_method,
                    max_count=20,
                    calldepth_filter=False):
    """Extract method and group them into list for heuristic processing"""
    init_dict = {}
    method_list = []
    instance_method_list = []
    static_method_list = []
    for func_elem in yaml_dict['All functions']['Elements']:
        # Check and filter method if too many methods in the result method list
        if len(method_list) > max_method or len(
                static_method_list) > max_method:
            method_list, static_method_list = _filter_method(
                method_list, static_method_list, max_count, calldepth_filter)

        # Still too many method after filtering, return the current result set
        if len(static_method_list) > max_method or len(
                method_list) > max_method:
            return init_dict, method_list, instance_method_list, static_method_list

        # Skip method belongs to non public or non concrete class
        if not func_elem['JavaMethodInfo']['classPublic']:
            continue
        if not func_elem['JavaMethodInfo']['classConcrete']:
            continue

        # Skip excluded methods
        if not func_elem['JavaMethodInfo']['public']:
            continue
        if not func_elem['JavaMethodInfo']['concrete']:
            continue

        if "<init>" in func_elem['functionName']:
            init_list = []
            func_class = func_elem['functionSourceFile'].replace('$', '.')
            if func_class in init_dict.keys():
                init_list = init_dict[func_class]
            init_list.append(func_elem)
            init_dict[func_class] = init_list
            continue

        getter_setter, plain, test, object = _is_method_excluded(func_elem)

        # Skip excluded methods
        if len(func_elem['argTypes']) > 20:
            continue
        if test or object:
            continue
        if func_elem['JavaMethodInfo']['classEnum']:
            continue

        # Add candidates to result lists
        func_class_name = func_elem['functionSourceFile'].split("$")[0]
        if func_elem['JavaMethodInfo']['static']:
            # Exclude methods that does not require parameters
            if not plain and _is_project_class(func_class_name):
                static_method_list.append(func_elem)
        else:
            # Check if this method belongs to this project
            # or not and filter out unrelated methods
            # from dependencies or libraries
            if _is_project_class(func_class_name):
                instance_method_list.append(func_elem)
                # Exclude getters setters and methods
                # that do not take any arguments.
                if plain or getter_setter:
                    continue

                method_list.append(func_elem)

    # Final filtering of the method list
    method_list, static_method_list = _filter_method(method_list,
                                                     static_method_list,
                                                     max_count,
                                                     calldepth_filter)

    return init_dict, method_list, instance_method_list, static_method_list


def _extract_super_exceptions(exceptions):
    """
    Some predefined java exceptions, like IOException are
    super class of many custom exceptions. In java, if we
    catch the super class exception first, you cannot add
    additional statement to catch a subclass of that exception.
    In order to allow the logic to catch subclass exception first,
    it is necessary to extract the super class exception into
    a separate set and only catch them after all other exceptions
    has been caught. This method separates the exception set and
    return a set of normal exceptions and a set of java exceptions
    which normally is a superclass of many exceptions.
    """
    normal_exceptions = set()
    super_exceptions = set()

    for exception in exceptions:
        if exception.startswith("java"):
            super_exceptions.add(exception)
        else:
            normal_exceptions.add(exception)

    return normal_exceptions, super_exceptions


def _generate_heuristic_1(method_tuple, possible_targets, max_target):
    """Heuristic 1.
    Creates a single FuzzTarget for all method that satisfy all:
        - public class method which are not abstract or found in JDK library
        - have between 1-20 arguments
        - do not have "test" or "Demo" in the function name or class name
    The fuzz target is simply one that calls into the target class function with
    suitable primitive fuzz data or simple concrete public constructor

    Will also add proper exception handling based on the exception list
    provided by the frontend code.
    """
    HEURISTIC_NAME = "jvm-autofuzz-heuristics-1"

    _, _, _, static_method_list = method_tuple

    if len(possible_targets) > max_target:
        return

    for func_elem in static_method_list:
        if len(possible_targets) > max_target:
            return

        # Initialize base possible_target object
        possible_target = FuzzTarget(func_elem=func_elem)
        func_name = possible_target.function_name
        func_class = possible_target.function_class
        target_method_name = possible_target.function_target

        # Store function parameter list
        variable_list = []
        for argType in func_elem['argTypes']:
            arg_list = _handle_argument(argType.replace('$', '.'), None,
                                        possible_target, max_target, [])
            if arg_list:
                variable_list.append(arg_list[0])
        if len(variable_list) != len(func_elem['argTypes']):
            continue

        # Create the actual source
        fuzzer_source_code = "  // Heuristic name: %s\n" % (HEURISTIC_NAME)
        fuzzer_source_code += "  // Target method: %s\n" % (target_method_name)
        fuzzer_source_code += "  %s.%s(%s);\n" % (func_class, func_name,
                                                  ",".join(variable_list))

        exception_set = set(possible_target.exceptions_to_handle)
        if len(exception_set) > 0:
            fuzzer_source_code = "  try {\n" + fuzzer_source_code
            fuzzer_source_code += "  }\n"
            counter = 1

            exceptions, super_exceptions = _extract_super_exceptions(
                exception_set)
            for exc in list(exceptions) + list(super_exceptions):
                fuzzer_source_code += "  catch (%s e%d) {}\n" % (exc, counter)
                counter += 1

        possible_target.fuzzer_source_code = fuzzer_source_code
        if HEURISTIC_NAME not in possible_target.heuristics_used:
            possible_target.heuristics_used.append(HEURISTIC_NAME)

        possible_targets.append(possible_target)


def _generate_heuristic_2(method_tuple, possible_targets, max_target):
    """Heuristic 2.
    Creates a FuzzTarget for each method that satisfy all:
        - public object method which are not abstract or found in JDK library
        - have between 1-20 arguments
        - do not have "test" or "demo" in the function name or class name
    The fuzz target is simply one that calls into the target function with
    seeded fuzz data. It will create the object with the class constructor
    before calling the function. Primitive type will be passed with the seeded
    fuzz data.

    Will also add proper exception handling based on the exception list
    provided by the frontend code.
    """
    HEURISTIC_NAME = "jvm-autofuzz-heuristics-2"

    init_dict, method_list, _, _ = method_tuple

    for func_elem in method_list:
        if len(possible_targets) > max_target:
            return

        # Initialize base possible_target object
        possible_target = FuzzTarget(func_elem=func_elem)
        func_name = possible_target.function_name
        func_class = possible_target.function_class
        target_method_name = possible_target.function_target

        # Get all possible argument lists with different possible object creation combination
        for argType in func_elem['argTypes']:
            arg_list = _handle_argument(argType.replace('$', '.'), init_dict,
                                        possible_target, max_target, [])
            if arg_list:
                possible_target.variables_to_add.append(arg_list[0])
        if len(possible_target.variables_to_add) != len(func_elem['argTypes']):
            continue

        # Get all object creation statement for each possible concrete classes of the object
        object_creation_list = _handle_object_creation(func_class, init_dict,
                                                       possible_target,
                                                       max_target, [])

        for object_creation_item in list(set(object_creation_list)):
            # Create possible target for all possible object creation statement
            # Clone the base target object
            cloned_possible_target = FuzzTarget(orig=possible_target)
            exception_set = set(cloned_possible_target.exceptions_to_handle)

            # Create the actual source
            fuzzer_source_code = "  // Heuristic name: %s\n" % (HEURISTIC_NAME)
            fuzzer_source_code += "  // Target method: %s\n" % (
                target_method_name)
            fuzzer_source_code += "  %s obj = %s;\n" % (func_class,
                                                        object_creation_item)
            fuzzer_source_code += "  obj.%s($VARIABLE$);\n" % (func_name)
            if len(exception_set) > 0:
                fuzzer_source_code = "  try {\n" + fuzzer_source_code
                fuzzer_source_code += "  }\n"
                counter = 1

                exceptions, super_exceptions = _extract_super_exceptions(
                    exception_set)
                for exc in list(exceptions) + list(super_exceptions):
                    fuzzer_source_code += "  catch (%s e%d) {}\n" % (exc,
                                                                     counter)
                    counter += 1

            cloned_possible_target.fuzzer_source_code = fuzzer_source_code
            if HEURISTIC_NAME not in cloned_possible_target.heuristics_used:
                cloned_possible_target.heuristics_used.append(HEURISTIC_NAME)

            possible_targets.append(cloned_possible_target)


def _generate_heuristic_3(method_tuple, possible_targets, max_target):
    """Heuristic 3.
    Creates a FuzzTarget for each method that satisfy all:
        - public object method which are not abstract or found in JDK library
        - have between 1-20 arguments
        - do not have "test" or "demo" in the function name or class name
    and Object creation method that satisfy all:
        - public static method which are not abstract
        - have less than 20 primitive arguments
        - do not have "test" or "demo" in the function name or class name
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

    init_dict, method_list, _, static_method_list = method_tuple
    for func_elem in method_list:
        if len(possible_targets) > max_target:
            return

        # Initialize base possible_target object
        possible_target = FuzzTarget(func_elem=func_elem)
        func_name = possible_target.function_name
        func_class = possible_target.function_class
        target_method_name = possible_target.function_target

        # Store function parameter list
        for argType in func_elem['argTypes']:
            arg_list = _handle_argument(argType.replace('$', '.'), None,
                                        possible_target, max_target, [])
            if arg_list:
                possible_target.variables_to_add.append(arg_list[0])
        if len(possible_target.variables_to_add) != len(func_elem['argTypes']):
            continue

        # Retrieve list of factory method for the target object
        factory_method_list = _search_static_factory_method(
            func_class, static_method_list, possible_target, max_target)

        for factory_method in list(set(factory_method_list)):
            # Create possible target for all possible factory method
            # Clone the base target object
            cloned_possible_target = FuzzTarget(orig=possible_target)

            # Create the actual source
            fuzzer_source_code = "  // Heuristic name: %s\n" % (HEURISTIC_NAME)
            fuzzer_source_code += "  // Target method: %s\n" % (
                target_method_name)
            fuzzer_source_code += "  %s obj = %s;\n" % (func_class,
                                                        factory_method)
            fuzzer_source_code += "  obj.%s($VARIABLE$);\n" % (func_name)

            exception_set = set(cloned_possible_target.exceptions_to_handle)
            if len(exception_set) > 0:
                fuzzer_source_code = "  try {\n" + fuzzer_source_code
                fuzzer_source_code += "  }\n"
                counter = 1

                exceptions, super_exceptions = _extract_super_exceptions(
                    exception_set)
                for exc in list(exceptions) + list(super_exceptions):
                    fuzzer_source_code += "  catch (%s e%d) {}\n" % (exc,
                                                                     counter)
                    counter += 1

            cloned_possible_target.fuzzer_source_code = fuzzer_source_code
            if HEURISTIC_NAME not in cloned_possible_target.heuristics_used:
                cloned_possible_target.heuristics_used.append(HEURISTIC_NAME)

            possible_targets.append(cloned_possible_target)


def _generate_heuristic_4(method_tuple, possible_targets, max_target):
    """Heuristic 4.
    Creates a FuzzTarget for each method that satisfy all:
        - public object method which are not abstract or found in JDK library
        - have between 1-20 arguments
        - do not have "test" or "demo" in the function name or class name
    and Object creation method that satisfy all:
        - public non-static method which are not abstract
        - have less than 20 arguments
        - do not have "test" or "demo" in the function name or class name
        - return an object of the needed class
    Similar to Heuristic 3, instead of static factory method, it will find
    non-static factory method instead.

    Will also add proper exception handling based on the exception list
    provided by the frontend code.
    """
    HEURISTIC_NAME = "jvm-autofuzz-heuristics-4"

    init_dict, method_list, instance_method_list, static_method_list = method_tuple
    for func_elem in method_list:
        if len(possible_targets) > max_target:
            return

        # Initialize base possible_target object
        possible_target = FuzzTarget(func_elem=func_elem)
        func_name = possible_target.function_name
        func_class = possible_target.function_class
        target_method_name = possible_target.function_target

        # Store function parameter list
        for argType in func_elem['argTypes']:
            arg_list = _handle_argument(argType.replace('$', '.'), None,
                                        possible_target, max_target, [])
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

        for factory_method in list(set(factory_method_list)):
            # Create possible target for all possible factory method
            # Clone the base target object
            cloned_possible_target = FuzzTarget(orig=possible_target)

            # Create the actual source
            fuzzer_source_code = "  // Heuristic name: %s\n" % (HEURISTIC_NAME)
            fuzzer_source_code += "  // Target method: %s\n" % (
                target_method_name)
            fuzzer_source_code += "  %s obj = %s;\n" % (func_class,
                                                        factory_method)
            fuzzer_source_code += "  obj.%s($VARIABLE$);\n" % (func_name)

            exception_set = set(cloned_possible_target.exceptions_to_handle)
            if len(exception_set) > 0:
                fuzzer_source_code = "  try {\n" + fuzzer_source_code
                fuzzer_source_code += "  }\n"
                counter = 1

                exceptions, super_exceptions = _extract_super_exceptions(
                    exception_set)
                for exc in list(exceptions) + list(super_exceptions):
                    fuzzer_source_code += "  catch (%s e%d) {}\n" % (exc,
                                                                     counter)
                    counter += 1

            cloned_possible_target.fuzzer_source_code = fuzzer_source_code
            if HEURISTIC_NAME not in cloned_possible_target.heuristics_used:
                cloned_possible_target.heuristics_used.append(HEURISTIC_NAME)

            possible_targets.append(cloned_possible_target)


def _generate_heuristic_6(method_tuple, possible_targets, max_target):
    """Heuristic 6.
    Creates a FuzzTarget for each method that satisfy all:
        - public object method which are not abstract or found in JDK library
        - have between 1-20 arguments
        - do not have "test" or "demo" in the function name or class name
        - require certain pre-settings before use (by calling all non-static
          method of the same class which does not have return values or start with
          set, except the target function itself)

    Will also add proper exception handling based on the exception list
    provided by the frontend code.
    """
    HEURISTIC_NAME = "jvm-autofuzz-heuristics-6"

    init_dict, method_list, instance_method_list, static_method_list = method_tuple
    for func_elem in method_list:
        if len(possible_targets) > max_target:
            return

        # Initialize base possible_target object
        possible_target = FuzzTarget(func_elem=func_elem)
        func_name = possible_target.function_name
        func_class = possible_target.function_class
        target_method_name = possible_target.function_target

        # Store function parameter list
        # Skip this method if it does not take at least one
        # enum object as parameter
        for argType in func_elem['argTypes']:
            arg_list = _handle_argument(argType.replace('$', '.'), init_dict,
                                        possible_target, max_target, [])
            if arg_list:
                possible_target.variables_to_add.append(arg_list[0])

        if len(possible_target.variables_to_add) != len(func_elem['argTypes']):
            continue

        # Retrieve list of factory method or constructor for the target object
        object_creation_list = _search_factory_method(func_class,
                                                      static_method_list,
                                                      instance_method_list,
                                                      possible_target,
                                                      init_dict, max_target)
        object_creation_list.extend(
            _search_static_factory_method(func_class, static_method_list,
                                          possible_target, max_target))
        object_creation_list.extend(
            _handle_object_creation(func_class, init_dict, possible_target,
                                    max_target, []))

        for object_creation in list(set(object_creation_list)):
            # Create possible target for all possible factory method
            # Clone the base target object
            cloned_possible_target = FuzzTarget(orig=possible_target)

            # Create the actual source
            fuzzer_source_code = "  // Heuristic name: %s\n" % (HEURISTIC_NAME)
            fuzzer_source_code += "  // Target method: %s\n" % (
                target_method_name)
            fuzzer_source_code += "  %s obj = %s;\n" % (func_class,
                                                        object_creation)
            for settings in _search_setting_method(instance_method_list,
                                                   func_class, func_name,
                                                   possible_target,
                                                   max_target):
                fuzzer_source_code += "  %s;\n" % (settings)
            fuzzer_source_code += "  obj.%s($VARIABLE$);\n" % (func_name)

            exception_set = set(cloned_possible_target.exceptions_to_handle)
            if len(exception_set) > 0:
                fuzzer_source_code = "  try {\n" + fuzzer_source_code
                fuzzer_source_code += "  }\n"
                counter = 1

                exceptions, super_exceptions = _extract_super_exceptions(
                    exception_set)
                for exc in list(exceptions) + list(super_exceptions):
                    fuzzer_source_code += "  catch (%s e%d) {}\n" % (exc,
                                                                     counter)
                    counter += 1

            cloned_possible_target.fuzzer_source_code = fuzzer_source_code
            if HEURISTIC_NAME not in cloned_possible_target.heuristics_used:
                cloned_possible_target.heuristics_used.append(HEURISTIC_NAME)

            possible_targets.append(cloned_possible_target)


def _generate_heuristic_7(method_tuple, possible_targets, max_target):
    """Heuristic 7.
    Creates a FuzzTarget for each method that satisfy all:
        - public static or object method which are not abstract or found in JDK library
        - have between 1-20 arguments
        - do not have "test" or "demo" in the function name or class name
        - have return value

    This heuristic adds in assert logic to confirm the consistency of method call. That
    is using the same set of parameters to invoke a method will always return the same
    result.

    Will also add proper exception handling based on the exception list
    provided by the frontend code.
    """
    HEURISTIC_NAME = "jvm-autofuzz-heuristics-7"

    init_dict, method_list, instance_method_list, static_method_list = method_tuple
    for func_elem in method_list + static_method_list:
        if len(possible_targets) > max_target:
            return

        # Skip method with no return value
        func_return_type = func_elem['returnType'].replace('$', '.')
        if not func_return_type or func_return_type == "void":
            continue

        # Distinguish static or object method
        if func_elem in method_list:
            static = False
        else:
            static = True

        # Initialize base possible_target object
        possible_target = FuzzTarget(func_elem=func_elem)
        func_name = possible_target.function_name
        func_class = possible_target.function_class
        target_method_name = possible_target.function_target

        # Store function parameter list
        # Skip this method if it does not take at least one
        # enum object as parameter
        arg_tuple_list = []
        for argType in func_elem['argTypes']:
            arg_list = _handle_argument(argType.replace('$', '.'),
                                        init_dict,
                                        possible_target,
                                        max_target, [],
                                        enum_object=True)
            if arg_list:
                arg_tuple_list.append((argType.replace('$', '.'), arg_list[0]))

        if len(arg_tuple_list) != len(func_elem['argTypes']):
            continue

        # Retrieve list of factory method for the target object
        object_creation_list = _search_factory_method(func_class,
                                                      static_method_list,
                                                      instance_method_list,
                                                      possible_target,
                                                      init_dict, max_target)
        object_creation_list.extend(
            _search_static_factory_method(func_class, static_method_list,
                                          possible_target, max_target))
        object_creation_list.extend(
            _handle_object_creation(func_class, init_dict, possible_target,
                                    max_target, []))

        for object_creation in list(set(object_creation_list)):
            # Create possible target for all possible factory method
            # Clone the base target object
            cloned_possible_target = FuzzTarget(orig=possible_target)

            # Create the actual source
            fuzzer_source_code = "  // Heuristic name: %s\n" % (HEURISTIC_NAME)
            fuzzer_source_code += "  // Target method: %s\n" % (
                target_method_name)

            # Create fix parameters from random data
            arg_counter = 1
            variable_list = []
            for arg_tuple in arg_tuple_list:
                fuzzer_source_code += "  %s arg%d = %s;\n" % (
                    arg_tuple[0], arg_counter, arg_tuple[1])
                variable_list.append("arg%d" % arg_counter)
                arg_counter += 1

            # Invoke static or object method with fixed parameters (from random data)
            # and assert for consistency
            if static:
                fuzzer_source_code += "  %s result1 = %s.%s(%s);\n" % (
                    func_return_type, func_class, func_name,
                    ",".join(variable_list))
                fuzzer_source_code += "  %s result2 = %s.%s(%s);\n" % (
                    func_return_type, func_class, func_name,
                    ",".join(variable_list))
            else:
                fuzzer_source_code += "  %s obj = %s;\n" % (func_class,
                                                            object_creation)
                fuzzer_source_code += "  %s result1 = obj.%s(%s);\n" % (
                    func_return_type, func_name, ",".join(variable_list))
                fuzzer_source_code += "  %s result2 = obj.%s(%s);\n" % (
                    func_return_type, func_name, ",".join(variable_list))
            fuzzer_source_code += '  assert result1.equals(result2) : "Result not match.";\n'

            exception_set = set(cloned_possible_target.exceptions_to_handle)
            if len(exception_set) > 0:
                fuzzer_source_code = "  try {\n" + fuzzer_source_code
                fuzzer_source_code += "  }\n"
                counter = 1

                exceptions, super_exceptions = _extract_super_exceptions(
                    exception_set)
                for exc in list(exceptions) + list(super_exceptions):
                    fuzzer_source_code += "  catch (%s e%d) {}\n" % (exc,
                                                                     counter)
                    counter += 1

            cloned_possible_target.fuzzer_source_code = fuzzer_source_code
            if HEURISTIC_NAME not in cloned_possible_target.heuristics_used:
                cloned_possible_target.heuristics_used.append(HEURISTIC_NAME)

            possible_targets.append(cloned_possible_target)


def _generate_heuristic_8(method_tuple, possible_targets, max_target):
    """Heuristic 8.
    Creates a FuzzTarget for each method that satisfy all:
        - public object method which are not abstract or found in JDK library
        - have between 1-20 arguments
        - do not have "test" or "demo" in the function name or class name
        - require enum object as parameter

    Will also add proper exception handling based on the exception list
    provided by the frontend code.
    """
    HEURISTIC_NAME = "jvm-autofuzz-heuristics-8"

    init_dict, method_list, instance_method_list, static_method_list = method_tuple
    for func_elem in method_list:
        if len(possible_targets) > max_target:
            return

        # Initialize base possible_target object
        possible_target = FuzzTarget(func_elem=func_elem)
        func_name = possible_target.function_name
        func_class = possible_target.function_class
        target_method_name = possible_target.function_target

        # Store function parameter list
        # Skip this method if it does not take at least one
        # enum object as parameter
        enum_argument = False
        for argType in func_elem['argTypes']:
            if _is_enum_class(init_dict, argType.replace('$', '.')):
                enum_argument = True
            arg_list = _handle_argument(argType.replace('$', '.'),
                                        init_dict,
                                        possible_target,
                                        max_target, [],
                                        enum_object=True)
            if arg_list:
                possible_target.variables_to_add.append(arg_list[0])

        if len(possible_target.variables_to_add) != len(func_elem['argTypes']):
            continue
        if not enum_argument:
            continue

        # Retrieve list of factory method for the target object
        object_creation_list = _search_factory_method(func_class,
                                                      static_method_list,
                                                      instance_method_list,
                                                      possible_target,
                                                      init_dict, max_target)
        object_creation_list.extend(
            _search_static_factory_method(func_class, static_method_list,
                                          possible_target, max_target))
        object_creation_list.extend(
            _handle_object_creation(func_class, init_dict, possible_target,
                                    max_target, []))

        for object_creation in list(set(object_creation_list)):
            # Create possible target for all possible factory method
            # Clone the base target object
            cloned_possible_target = FuzzTarget(orig=possible_target)

            # Create the actual source
            fuzzer_source_code = "  // Heuristic name: %s\n" % (HEURISTIC_NAME)
            fuzzer_source_code += "  // Target method: %s\n" % (
                target_method_name)
            fuzzer_source_code += "  %s obj = %s;\n" % (func_class,
                                                        object_creation)
            fuzzer_source_code += "  obj.%s($VARIABLE$);\n" % (func_name)

            exception_set = set(cloned_possible_target.exceptions_to_handle)
            if len(exception_set) > 0:
                fuzzer_source_code = "  try {\n" + fuzzer_source_code
                fuzzer_source_code += "  }\n"
                counter = 1

                exceptions, super_exceptions = _extract_super_exceptions(
                    exception_set)
                for exc in list(exceptions) + list(super_exceptions):
                    fuzzer_source_code += "  catch (%s e%d) {}\n" % (exc,
                                                                     counter)
                    counter += 1

            cloned_possible_target.fuzzer_source_code = fuzzer_source_code
            if HEURISTIC_NAME not in cloned_possible_target.heuristics_used:
                cloned_possible_target.heuristics_used.append(HEURISTIC_NAME)

            possible_targets.append(cloned_possible_target)


def _generate_heuristic_9(method_tuple, possible_targets, max_target):
    """Heuristic 9.
    Creates a FuzzTarget for each method that satisfy all:
        - public object method which are not abstract or found in JDK library
        - have between 1-20 arguments
        - do not have "test" or "demo" in the function name or class name

    Use public static final object defined in the target class for getting
    the needed object

    Will also add proper exception handling based on the exception list
    provided by the frontend code.
    """
    HEURISTIC_NAME = "jvm-autofuzz-heuristics-9"

    init_dict, method_list, instance_method_list, static_method_list = method_tuple
    for func_elem in method_list:
        if len(possible_targets) > max_target:
            return

        # Initialize base possible_target object
        possible_target = FuzzTarget(func_elem=func_elem)
        func_name = possible_target.function_name
        func_class = possible_target.function_class
        target_method_name = possible_target.function_target

        # Store function parameter list
        # Skip this method if it does not take at least one
        # enum object as parameter
        for argType in func_elem['argTypes']:
            arg_list = _handle_argument(argType.replace('$', '.'),
                                        init_dict,
                                        possible_target,
                                        max_target, [],
                                        enum_object=True,
                                        class_field=True)
            if arg_list:
                possible_target.variables_to_add.append(arg_list[0])

        if len(possible_target.variables_to_add) != len(func_elem['argTypes']):
            continue

        # Retrieve list of factory method for the target object
        object_creation_list = _search_factory_method(func_class,
                                                      static_method_list,
                                                      instance_method_list,
                                                      possible_target,
                                                      init_dict,
                                                      max_target,
                                                      class_field=True)
        object_creation_list.extend(
            _search_static_factory_method(func_class, static_method_list,
                                          possible_target, max_target))
        object_creation_list.extend(
            _handle_object_creation(func_class,
                                    init_dict,
                                    possible_target,
                                    max_target, [],
                                    class_field=True))

        for object_creation in list(set(object_creation_list)):
            # Create possible target for all possible factory method
            # Clone the base target object
            cloned_possible_target = FuzzTarget(orig=possible_target)

            # Create the actual source
            fuzzer_source_code = "  // Heuristic name: %s\n" % (HEURISTIC_NAME)
            fuzzer_source_code += "  // Target method: %s\n" % (
                target_method_name)
            fuzzer_source_code += "  %s obj = %s;\n" % (func_class,
                                                        object_creation)
            fuzzer_source_code += "  obj.%s($VARIABLE$);\n" % (func_name)

            exception_set = set(cloned_possible_target.exceptions_to_handle)
            if len(exception_set) > 0:
                fuzzer_source_code = "  try {\n" + fuzzer_source_code
                fuzzer_source_code += "  }\n"
                counter = 1

                exceptions, super_exceptions = _extract_super_exceptions(
                    exception_set)
                for exc in list(exceptions) + list(super_exceptions):
                    fuzzer_source_code += "  catch (%s e%d) {}\n" % (exc,
                                                                     counter)
                    counter += 1

            cloned_possible_target.fuzzer_source_code = fuzzer_source_code
            if HEURISTIC_NAME not in cloned_possible_target.heuristics_used:
                cloned_possible_target.heuristics_used.append(HEURISTIC_NAME)

            possible_targets.append(cloned_possible_target)


def _generate_heuristic_10(method_tuple, possible_targets, max_target):
    """Heuristic 10.
    Creates a FuzzTarget for each method that satisfy all:
        - public object or static method which are not abstract or found in JDK library
        - have between 1-20 arguments
        - do not have "test" or "demo" in the function name or class name
        - Have at least one arguments required a class object.

    Will also add proper exception handling based on the exception list
    provided by the frontend code.
    """
    HEURISTIC_NAME = "jvm-autofuzz-heuristics-10"

    global need_param_combination
    init_dict, method_list, instance_method_list, static_method_list = method_tuple
    for func_elem in method_list + static_method_list:
        if len(possible_targets) > max_target:
            return

        # Skip method without using at least one class object
        if "java.lang.Class" not in func_elem['argTypes']:
            continue

        # Initialize base possible_target object
        possible_target = FuzzTarget(func_elem=func_elem)
        func_name = possible_target.function_name
        func_class = possible_target.function_class
        target_method_name = possible_target.function_target

        # Store function parameter list
        # Skip this method if it does not take at least one
        # enum object as parameter
        arg_lists = []
        for argType in func_elem['argTypes']:
            arg_list = _handle_argument(argType.replace('$', '.'),
                                        init_dict,
                                        possible_target,
                                        max_target, [],
                                        enum_object=True,
                                        class_field=True,
                                        class_object=True)
            if arg_list:
                if argType == "java.lang.Class":
                    list_to_append = arg_list
                else:
                    list_to_append = []
                    list_to_append.append(arg_list[0])

                arg_lists.append(list_to_append)

        if len(arg_lists) != len(func_elem['argTypes']):
            continue

        # Retrieve list of factory method for the target object
        object_creation_list = _search_factory_method(func_class,
                                                      static_method_list,
                                                      instance_method_list,
                                                      possible_target,
                                                      init_dict,
                                                      max_target,
                                                      class_field=True,
                                                      class_object=True)
        object_creation_list.extend(
            _search_static_factory_method(func_class,
                                          static_method_list,
                                          possible_target,
                                          max_target,
                                          class_object=True))
        object_creation_list.extend(
            _handle_object_creation(func_class,
                                    init_dict,
                                    possible_target,
                                    max_target, [],
                                    class_field=True,
                                    class_object=True))

        for object_creation in list(set(object_creation_list)):
            # Create possible target for all possible factory method
            # Clone the base target object
            cloned_possible_target = FuzzTarget(orig=possible_target)

            # Create the actual source
            fuzzer_source_code = "  // Heuristic name: %s\n" % (HEURISTIC_NAME)
            fuzzer_source_code += "  // Target method: %s\n" % (
                target_method_name)
            fuzzer_source_code += "  %s obj = %s;\n" % (func_class,
                                                        object_creation)
            fuzzer_source_code += "  obj.%s($VARIABLE$);\n" % (func_name)

            exception_set = set(cloned_possible_target.exceptions_to_handle)
            if len(exception_set) > 0:
                fuzzer_source_code = "  try {\n" + fuzzer_source_code
                fuzzer_source_code += "  }\n"
                counter = 1

                exceptions, super_exceptions = _extract_super_exceptions(
                    exception_set)
                for exc in list(exceptions) + list(super_exceptions):
                    fuzzer_source_code += "  catch (%s e%d) {}\n" % (exc,
                                                                     counter)
                    counter += 1

            cloned_possible_target.fuzzer_source_code = fuzzer_source_code
            if HEURISTIC_NAME not in cloned_possible_target.heuristics_used:
                cloned_possible_target.heuristics_used.append(HEURISTIC_NAME)

            for arg_list in list(itertools.product(*arg_lists)):
                cross_product_possible_target = FuzzTarget(
                    orig=cloned_possible_target)
                cross_product_possible_target.variables_to_add = arg_list
                possible_targets.append(cross_product_possible_target)
                if not need_param_combination:
                    break


def _generate_heuristics(yaml_dict,
                         max_target,
                         max_method,
                         calldepth_filter=False):
    method_tuple = _extract_method(yaml_dict,
                                   max_method,
                                   max_count=20,
                                   calldepth_filter=calldepth_filter)

    possible_targets = []
    temp_targets = []
    _generate_heuristic_1(method_tuple, temp_targets, max_target)
    possible_targets.extend(temp_targets)
    temp_targets = []
    _generate_heuristic_2(method_tuple, temp_targets, max_target)
    possible_targets.extend(temp_targets)
    temp_targets = []
    _generate_heuristic_3(method_tuple, temp_targets, max_target)
    possible_targets.extend(temp_targets)
    temp_targets = []
    _generate_heuristic_4(method_tuple, temp_targets, max_target)
    possible_targets.extend(temp_targets)
    temp_targets = []
    _generate_heuristic_6(method_tuple, temp_targets, max_target)
    possible_targets.extend(temp_targets)
    temp_targets = []
    _generate_heuristic_7(method_tuple, temp_targets, max_target)
    possible_targets.extend(temp_targets)
    temp_targets = []
    _generate_heuristic_8(method_tuple, temp_targets, max_target)
    possible_targets.extend(temp_targets)
    temp_targets = []
    _generate_heuristic_9(method_tuple, temp_targets, max_target)
    possible_targets.extend(temp_targets)
    temp_targets = []
    _generate_heuristic_10(method_tuple, temp_targets, max_target)
    possible_targets.extend(temp_targets)

    return possible_targets


def generate_possible_targets(proj_folder, class_list, max_target,
                              param_combination):
    """Generate all possible targets for a given project folder"""

    # Set param_combination to global
    global need_param_combination
    need_param_combination = param_combination

    # Set the project_class_list to global
    global project_class_list
    project_class_list = class_list

    # Read the Fuzz Introspector generated data as a method tuple
    yaml_file = os.path.join(proj_folder, "work",
                             "fuzzerLogFile-Fuzz.data.yaml")
    with open(yaml_file, "r") as stream:
        yaml_dict = yaml.safe_load(stream)

    max_fuzzer = constants.MAX_FUZZERS_PER_PROJECT

    possible_targets = _generate_heuristics(yaml_dict, max_target, max_fuzzer,
                                            False)
    if len(possible_targets) > max_fuzzer:
        possible_targets = _generate_heuristics(yaml_dict, max_target, True)

    return possible_targets
