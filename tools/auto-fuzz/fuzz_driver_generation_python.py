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

from typing import List, Any


class FuzzTarget:
    function_target: str
    exceptions_to_handle: List[str]
    fuzzer_source_code: str
    variables_to_add: List[Any]
    imports_to_add: List[str]

    def __init__(self):
        self.function_target = ""
        self.exceptions_to_handle = []
        self.fuzzer_source_code = ""
        self.variables_to_add = []
        self.imports_to_add = []

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

        # Generate lines for importing necessary modules.
        import_to_add = "# Imports by the generated code\n"
        for fuzz_import in self.imports_to_add:
            import_to_add += "%s\n" % (fuzz_import)

        # Open the base fuzzer and patch while reading through the file.
        with open(filename, "r") as f:
            for line in f:
                content += line

                # Add imports string after "import atheris"
                if "import atheris" in line:
                    content += import_to_add

                # Add the fuzzer code after creation of the fuzzed data provider.
                if "fdp = atheris.FuzzedDataProvider(data)" in line:

                    # First add the variables that should be seeded with fuzz data.
                    for var_name, var_type in self.variables_to_add:
                        if var_type == "str":
                            content += f"  {var_name} = fdp.ConsumeUnicodeNoSurrogates(24)\n"
                        if var_type == "filename-b":
                            content += (
                                f"  {var_name} = '/tmp/random_file.txt'\n"
                                f"  with open({var_name}, 'wb') as f:\n"
                                f"    f.write(fdp.ConsumeBytes(1024))\n")

                        content += "\n"

                    # Add core source code of the target, that calls into the
                    # given package.
                    content += self.fuzzer_source_code

        return content


def find_all_exceptions(elem, elements):
    exceptions = set()
    for exc in elem['raised']:
        exceptions.add(exc)
    worklist = elem['functionsReached']
    handled = set()
    while len(worklist) > 0:
        target = worklist.pop()
        if target in handled:
            continue
        handled.add(target)

        # Find the target
        for t_elem in elements:
            if t_elem['functionName'] == target:
                worklist += t_elem['functionsReached']
                for t_exc in t_elem['raised']:
                    exceptions.add(t_exc)
    return exceptions


def get_exception_imports(exceptions_thrown, all_classes, inheritance):
    refined = []
    inherited_from_exception = set()
    for except_thrown in exceptions_thrown:
        added = False
        for cls in all_classes:
            if cls.split(".")[-1] == except_thrown:
                # Cut out the initial dir
                refined.append(".".join(cls.split(".")[1:]))
                added = True
        if not added:
            refined.append(except_thrown)

    # Find exceptions that inherits directly from Exception, as these are
    # often the highest-level exceptions from a library, so we want to
    # prioritise those.
    for cls_inh in inheritance:
        inherited_froms = inheritance[cls_inh]
        for inh_from in inherited_froms:
            if inh_from == "Exception":
                split_from = ".".join(cls_inh.split(".")[1:])
                inherited_from_exception.add(split_from)

    # If we have some exceptions that are top-level, we will use those
    # for catching.
    if len(inherited_from_exception) > 0:
        return list(inherited_from_exception)

    # Otheriwse, return the more fine-grained
    return refined


def get_refined_importing(func_name):
    import_path = ".".join(func_name.split(".")[:-1])
    import_func = func_name.split(".")[-1]
    refined_import = "from %s import %s as fuzz_target" % (import_path,
                                                           import_func)
    return "fuzz_target", refined_import


def cleanup_import(import_str):
    split_import_str = import_str.split(".")
    try:
        if split_import_str[0] == "src":
            return split_import_str[1]
    except:
        pass
    return split_import_str[0]


def give_right_path(import_str):
    split_import_str = import_str.split(".")
    try:
        if split_import_str[1] == "src":
            return ".".join(split_import_str[2:])
    except:
        pass
    return ".".join(split_import_str[1:])


def _generate_heuristic_1(yaml_dict, possible_targets):
    """Heuristic 1.
    Creates a FuzzTarget for each function that satisfy all:
        - have between 1-20 arguments
        - do not have "self" in the argument name of the first argument
        - do not have "test" in the function name

    The fuzz target is simply one that calls into the target function with
    a string seeded with fuzz data.

    Will also add proper exception handling based on each raise instruction of
    all the reachable functions from the target function.
    """
    HEURISTIC_NAME = "Heuristic 1"
    for func_elem in yaml_dict['All functions']['Elements']:
        if func_elem['functionLinenumber'] != -1:
            if len(func_elem['argNames']) < 1 or len(
                    func_elem['argNames']) > 20:
                continue
            if 'self' in func_elem['argNames'][0]:
                continue
            if "test" in func_elem['functionName']:
                continue

            # We need to remove the first instance of the package
            # because this is what the directory is named
            func_name = func_elem['functionName']
            func_name = give_right_path(func_name)

            # Create the possible target
            possible_target = FuzzTarget()
            possible_target.function_target = func_name

            # Set exceptions raised
            exceptions_thrown = find_all_exceptions(
                func_elem, yaml_dict['All functions']['Elements'])
            exceptions_thrown = get_exception_imports(exceptions_thrown,
                                                      yaml_dict['All classes'],
                                                      yaml_dict['Inheritance'])
            possible_target.exceptions_to_handle = list(exceptions_thrown)

            # Set imports
            possible_target.imports_to_add.append("import %s" %
                                                  (cleanup_import(func_name)))

            # Create the actual source
            fuzzer_source_code = ""
            fuzzer_source_code += "  # Heuristic name: %s\n" % (HEURISTIC_NAME)
            fuzzer_source_code += "  try:\n"
            fuzzer_source_code += "    %s(val_1)\n" % (func_name)
            fuzzer_source_code += "  except ("
            for exc in possible_target.exceptions_to_handle:
                fuzzer_source_code += exc + ","
            fuzzer_source_code += "):\n    pass\n"
            possible_target.fuzzer_source_code = fuzzer_source_code

            # Set free variables and their types.
            possible_target.variables_to_add.append(("val_1", "str"))

            # Add to list of possible targets.
            possible_targets.append(possible_target)


def _generate_heuristic_2(yaml_dict, possible_targets):
    """Heuristic 2

    The same heuristic as heuristic 1, however, instead of calling the function
    directly, will import the target function differently, e.g.

    from package.name import interesting_function as fuzz_target

    and then use fuzz_target as the entrypoint of the fuzzer. This heuristic
    is needed for some packages that may have imports that overwrite certain
    attributes in modules. Python email-validator is a case of this.
    """
    HEURISTIC_NAME = "Heuristic 2"
    for func_elem in yaml_dict['All functions']['Elements']:
        if func_elem['functionLinenumber'] != -1:
            if len(func_elem['argNames']) < 1 or len(
                    func_elem['argNames']) > 20:
                continue
            if 'self' in func_elem['argNames'][0]:
                continue
            if "test" in func_elem['functionName']:
                continue

            # We need to remove the first instance of the package
            # because this is what the directory is named
            func_name = func_elem['functionName']
            func_name = give_right_path(func_name)

            # Create the possible target
            possible_target = FuzzTarget()
            possible_target.function_target = func_name

            # Set exceptions raised
            exceptions_thrown = find_all_exceptions(
                func_elem, yaml_dict['All functions']['Elements'])
            exceptions_thrown = get_exception_imports(exceptions_thrown,
                                                      yaml_dict['All classes'],
                                                      yaml_dict['Inheritance'])
            possible_target.exceptions_to_handle = list(exceptions_thrown)

            # Set imports
            r_fuzz_target, r_fuzz_import = get_refined_importing(func_name)
            possible_target.imports_to_add.append(r_fuzz_import)

            # Add the ordinary import as well
            possible_target.imports_to_add.append("import %s" %
                                                  (cleanup_import(func_name)))

            # Create the actual source
            fuzzer_source_code = ""
            fuzzer_source_code += "  # Heuristic name: %s\n" % (HEURISTIC_NAME)
            fuzzer_source_code += "  try:\n"
            fuzzer_source_code += "    %s(val_1)\n" % (r_fuzz_target)
            fuzzer_source_code += "  except ("
            for exc in possible_target.exceptions_to_handle:
                fuzzer_source_code += exc + ","
            fuzzer_source_code += "):\n    pass\n"
            possible_target.fuzzer_source_code = fuzzer_source_code

            # Set free variables and their types.
            possible_target.variables_to_add.append(("val_1", "str"))

            # Add to list of possible targets.
            possible_targets.append(possible_target)


def _generate_heuristic_3(yaml_dict, possible_targets):
    # Heuristic 1.1
    # For file writes
    HEURISTIC_NAME = "Heuristic 3"
    for func_elem in yaml_dict['All functions']['Elements']:
        if func_elem['functionLinenumber'] != -1:
            if len(func_elem['argNames']) < 1 or len(
                    func_elem['argNames']) > 50:
                continue
            if 'self' in func_elem['argNames'][0]:
                continue
            if "test" in func_elem['functionName']:
                continue

            # Sort out all that does not have a "file" in first argument
            if "file" not in func_elem['argNames'][0]:
                continue

            # We need to remove the first instance of the package
            # because this is what the directory is named
            func_name = func_elem['functionName']
            try:
                #func_name = ".".join(func_name.split(".")[1:])
                func_name = give_right_path(func_name)
            except:
                pass

            # Create the possible target
            possible_target = FuzzTarget()
            possible_target.function_target = func_name

            # Set exceptions raised
            exceptions_thrown = find_all_exceptions(
                func_elem, yaml_dict['All functions']['Elements'])
            # Add neccessary prefixes
            exceptions_thrown = get_exception_imports(exceptions_thrown,
                                                      yaml_dict['All classes'],
                                                      yaml_dict['Inheritance'])
            possible_target.exceptions_to_handle = list(exceptions_thrown)

            # Set imports
            #possible_target.imports_to_add.append(func_name.split(".")[0])
            possible_target.imports_to_add.append("import %s" %
                                                  (cleanup_import(func_name)))

            # Create the actual source
            fuzzer_source_code = ""
            fuzzer_source_code += "  # Heuristic name: %s\n" % (HEURISTIC_NAME)
            fuzzer_source_code += "  try:\n"
            fuzzer_source_code += "    %s(val_1)\n" % (func_name)
            fuzzer_source_code += "  except ("
            for exc in possible_target.exceptions_to_handle:
                fuzzer_source_code += exc + ","
            fuzzer_source_code += "):\n    pass\n"
            possible_target.fuzzer_source_code = fuzzer_source_code

            # Set free variables and their types.
            possible_target.variables_to_add.append(("val_1", "filename-b"))

            # Add to list of possible targets.
            possible_targets.append(possible_target)


def _generate_heuristic_4(yaml_dict, possible_targets):
    """Heuristic 4
    # Go through each class and call each function in the class on the created
    # object.
    """
    HEURISTIC_NAME = "Heuristic 4"
    all_classes = []
    for class_path in yaml_dict['All classes']:
        # Let's see if we find an init function
        init_name = class_path + ".__init__"
        init_elem = None
        for elem in yaml_dict['All functions']['Elements']:
            if init_name == elem['functionName']:
                init_elem = elem

        if init_elem is None:
            continue

        # Strip some prefixes off
        try:
            class_path = give_right_path(class_path)
        except:
            pass

        possible_class_targets = []
        for elem in yaml_dict['All functions']['Elements']:
            if class_path in elem['functionName'] and "__init__" not in elem[
                    'functionName'] and class_path != elem['functionName']:
                possible_class_targets.append(elem)

        # Create a possible target for each function in the object.
        for elem in possible_class_targets:
            exceptions_thrown = find_all_exceptions(
                elem, yaml_dict['All functions']['Elements'])
            # Add neccessary prefixes
            exceptions_thrown = get_exception_imports(exceptions_thrown,
                                                      yaml_dict['All classes'],
                                                      yaml_dict['Inheritance'])
            possible_target = FuzzTarget()
            possible_class_target_name = elem['functionName'].split(".")[-1]

            fuzzer_source_code = "  # Class target.\n"
            fuzzer_source_code += "  # Heuristic name: %s\n" % (HEURISTIC_NAME)
            fuzzer_source_code += "  try:\n"
            fuzzer_source_code += "    c1 = %s()\n" % (class_path)
            fuzzer_source_code += "    c1.%s(val_1)\n" % (
                possible_class_target_name)
            fuzzer_source_code += "  except("
            for exc in exceptions_thrown:
                fuzzer_source_code += exc + ","
            fuzzer_source_code += "):\n"
            fuzzer_source_code += "    pass\n"

            possible_target.fuzzer_source_code = fuzzer_source_code
            possible_target.imports_to_add.append("import %s" %
                                                  (cleanup_import(class_path)))

            # Add open variables
            possible_target.variables_to_add.append(("val_1", "str"))
            possible_targets.append(possible_target)

            # Make second one
            possible_target2 = FuzzTarget()
            possible_target2.imports_to_add = possible_target.imports_to_add
            possible_target2.variables_to_add = possible_target.variables_to_add
            fuzzer_source_code2 = "  # Class target.\n"
            fuzzer_source_code2 += "  # Heuristic name: %s .1\n" % (
                HEURISTIC_NAME)
            fuzzer_source_code2 += "  try:\n"
            fuzzer_source_code2 += "    c1 = %s(val_1)\n" % (class_path)
            fuzzer_source_code2 += "    c1.%s()\n" % (
                possible_class_target_name)
            fuzzer_source_code2 += "  except("
            for exc in exceptions_thrown:
                fuzzer_source_code2 += exc + ","
            fuzzer_source_code2 += "):\n"
            fuzzer_source_code2 += "    pass\n"
            possible_target2.fuzzer_source_code = fuzzer_source_code2

            possible_targets.append(possible_target2)


def generate_possible_targets(proj_folder):
    """Generate all possible targets for a given project folder"""

    # Read the Fuzz Introspector generated data
    yaml_file = os.path.join(proj_folder, "work",
                             "fuzzerLogFile-fuzz_1.data.yaml")
    with open(yaml_file, "r") as stream:
        yaml_dict = yaml.safe_load(stream)

    possible_targets = []
    _generate_heuristic_1(yaml_dict, possible_targets)
    _generate_heuristic_2(yaml_dict, possible_targets)
    _generate_heuristic_3(yaml_dict, possible_targets)
    _generate_heuristic_4(yaml_dict, possible_targets)

    return possible_targets