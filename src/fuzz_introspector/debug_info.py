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
"""Module for handling debug information from LLVM """

import logging
import os
import json
import shutil

from fuzz_introspector import constants

logger = logging.getLogger(name=__name__)


def extract_all_compile_units(content, all_files_in_debug_info):
    for line in content.split("\n"):
        # Source code files
        if "Compile unit:" in line:
            split_line = line.split(" ")
            file_dict = {
                'source_file': split_line[-1],
                'language': split_line[2]
            }

            # TODO: (David) remove this hack to frontend
            # LLVM may combine two absolute paths, which causes the
            # filepath to be erroneus.
            # Fix this here
            if '//' in file_dict['source_file']:
                file_dict['source_file'] = '/' + '/'.join(
                    file_dict['source_file'].split('//')[1:])

            all_files_in_debug_info[file_dict['source_file']] = file_dict


def extract_global_variables(content, global_variables, source_files):
    for line in content.split("\n"):
        if "Global variable: " in line:
            sline = line.replace("Global variable: ", "").split(" from ")
            global_variable_name = sline[0]
            location = sline[-1]
            source_file = location.split(":")[0]
            try:
                source_line = location.split(":")[1]
            except IndexError:
                source_line = "-1"
            global_variables[source_file + source_line] = {
                'name': global_variable_name,
                'source': {
                    'source_file': source_file,
                    'source_line': source_line
                }
            }
            # Add the file to all files in project
            if source_file not in source_files:
                source_files[source_file] = {
                    'source_file': source_file,
                    'language': 'N/A'
                }


def extract_types(content, all_types, all_files_in_debug_info):
    current_type = None
    current_struct = None
    types_identifier = "## Types defined in module"
    read_types = False

    for line in content.split("\n"):
        if types_identifier in line:
            read_types = True

        if read_types:
            if "Type: Name:" in line:
                if current_struct is not None:
                    hashkey = current_struct['source'][
                        'source_file'] + current_struct['source']['source_line']
                    all_types[hashkey] = current_struct
                    current_struct = None
                if "DW_TAG_structure" in line:
                    current_struct = dict()
                    struct_name = line.split("{")[-1].split("}")[0].strip()
                    location = line.split("from")[-1].strip().split(" ")[0]
                    source_file = location.split(":")[0]
                    try:
                        source_line = location.split(":")[1]
                    except IndexError:
                        source_line = "-1"
                    current_struct = {
                        'type': 'struct',
                        'name': struct_name,
                        'source': {
                            'source_file': source_file,
                            'source_line': source_line
                        },
                        'elements': []
                    }
                    # Add the file to all files in project
                    if source_file not in all_files_in_debug_info:
                        all_files_in_debug_info[source_file] = {
                            'source_file': source_file,
                            'language': 'N/A'
                        }
                if "DW_TAG_typedef" in line:
                    name = line.split("{")[-1].strip().split("}")[0]
                    location = line.split(" from ")[-1].split(" ")[0]
                    source_file = location.split(":")[0]
                    try:
                        source_line = location.split(":")[1]
                    except IndexError:
                        source_line = "-1"
                    current_type = {
                        'type': 'typedef',
                        'name': name,
                        'source': {
                            'source_file': source_file,
                            'source_line': source_line
                        }
                    }
                    hashkey = current_type['source'][
                        'source_file'] + current_type['source']['source_line']
                    all_types[hashkey] = current_type
                    # Add the file to all files in project
                    if source_file not in all_files_in_debug_info:
                        all_files_in_debug_info[source_file] = {
                            'source_file': source_file,
                            'language': 'N/A'
                        }
            if "- Elem " in line:
                # Ensure we have a strcuct
                if current_struct is not None:
                    elem_name = line.split("{")[-1].strip().split(" ")[0]
                    location = line.split("from")[-1].strip().split(" ")[0]
                    source_file = location.split(":")[0]
                    try:
                        source_line = location.split(":")[1]
                    except IndexError:
                        source_line = "-1"

                    current_struct['elements'].append({
                        'name': elem_name,
                        'source': {
                            'source_file': source_file,
                            'source_line': source_line,
                        }
                    })
                    # Add the file to all files in project
                    if source_file not in all_files_in_debug_info:
                        all_files_in_debug_info[source_file] = {
                            'source_file': source_file,
                            'language': 'N/A'
                        }


def extract_all_functions_in_debug_info(content, all_functions_in_debug,
                                        all_files_in_debug_info):
    function_identifier = "## Functions defined in module"
    read_functions = False
    current_function = None
    global_variable_identifier = "## Global variables in module"
    logger.info("Extracting functions")

    for line in content.split("\n"):
        if function_identifier in line:
            read_functions = True
        if global_variable_identifier in line:
            if current_function is not None:
                # Adjust args such that arg0 is set to the return type
                current_args = current_function.get('args', [])
                if len(current_args) > 0:
                    return_type = current_args[0]
                    current_args = current_args[1:]
                    current_function['args'] = current_args
                    current_function['return_type'] = return_type

                try:
                    hashkey = current_function['source'][
                        'source_file'] + current_function['source'][
                            'source_line']
                except KeyError:
                    hashkey = None

                if hashkey is not None:
                    # print("Actually adding 1: %s"%(current_function['name']))
                    all_functions_in_debug[hashkey] = current_function
                else:
                    # Something went wrong, abandon.
                    current_function = None
            read_functions = False

        if read_functions:
            if line.startswith("Subprogram: "):
                # print("Subprogram line: %s"%(line))
                if current_function is not None:
                    # Adjust args such that arg0 is set to the return type
                    current_args = current_function.get('args', [])
                    if len(current_args) > 0:
                        return_type = current_args[0]
                        current_args = current_args[1:]
                        current_function['args'] = current_args
                        current_function['return_type'] = return_type
                    try:
                        hashkey = current_function['source'][
                            'source_file'] + current_function['source'][
                                'source_line']
                    except KeyError:
                        hashkey = None

                    if hashkey is not None:
                        # print(
                        #  "Actually adding 2: %s :: to %s"%(current_function['name'], hashkey)
                        # )
                        all_functions_in_debug[hashkey] = current_function
                    else:
                        # Something went wrong, abandon.
                        current_function = None
                current_function = dict()
                function_name = " ".join(line.split(" ")[1:])
                # print("Adding function: %s"%(function_name))
                current_function['name'] = function_name
            if ' from ' in line and ":" in line and "- Operand" not in line and "Elem " not in line:
                location = line.split(" from ")[-1]
                source_file = location.split(":")[0].strip()
                try:
                    source_line = line.split(":")[-1].strip()
                    if len(source_line.split(" ")) > 0:
                        source_line = source_line.split(" ")[0]
                except IndexError:
                    source_line = "-1"
                current_function['source'] = {
                    'source_file': source_file,
                    'source_line': source_line,
                }
                # Add the file to all files in project
                if source_file not in all_files_in_debug_info:
                    all_files_in_debug_info[source_file] = {
                        'source_file': source_file,
                        'language': 'N/A'
                    }
            if ' - Operand' in line:

                # Decipher type
                current_args = current_function.get('args', [])
                if "Name: {" not in line:
                    l1 = line.replace("Operand Type:",
                                      "").replace("Type: ",
                                                  "").replace("-", "")
                    pointer_count = 0
                    const_count = 0
                    for arg_type in l1.split(","):
                        if "DW_TAG_pointer_type" in arg_type:
                            pointer_count += 1
                        if "DW_TAG_const_type" in arg_type:
                            const_count += 1
                    base_type = l1.split(",")[-1].strip()
                    end_type = ""
                    if const_count > 0:
                        end_type += "const "
                    end_type += base_type
                    if pointer_count > 0:
                        end_type += " "
                        end_type += "*" * pointer_count

                    current_args.append(end_type)
                elif "Name: " in line:
                    current_args.append(
                        line.split("{")[-1].split("}")[0].strip())
                else:
                    current_args.append(line)
                current_function['args'] = current_args


def load_debug_report(debug_files):
    all_files_in_debug_info = dict()
    all_functions_in_debug = dict()
    all_global_variables = dict()
    all_types = dict()
    print("Loading report:")

    # Extract all of the details
    for debug_file in debug_files:
        with open(debug_file, 'r') as debug_f:
            content = debug_f.read()

            extract_all_compile_units(content, all_files_in_debug_info)
            extract_all_functions_in_debug_info(content,
                                                all_functions_in_debug,
                                                all_files_in_debug_info)
            extract_global_variables(content, all_global_variables,
                                     all_files_in_debug_info)
            extract_types(content, all_types, all_files_in_debug_info)

    report_dict = {
        'all_files_in_project': list(all_files_in_debug_info.values()),
        'all_functions_in_project': list(all_functions_in_debug.values()),
        'all_global_variables': list(all_global_variables.values()),
        'all_types': list(all_types.values())
    }
    return report_dict


def dump_debug_report(report_dict):
    # Extract all files
    if not os.path.isdir(constants.SAVED_SOURCE_FOLDER):
        os.mkdir(constants.SAVED_SOURCE_FOLDER)

    for file_elem in report_dict['all_files_in_project']:
        if not os.path.isfile(file_elem['source_file']):
            logger.info("No such file: %s" % (file_elem['source_file']))
            continue
        dst = constants.SAVED_SOURCE_FOLDER + '/' + file_elem['source_file']
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copy(file_elem['source_file'], dst)

    with open(constants.DEBUG_INFO_DUMP, 'w') as debug_dump:
        debug_dump.write(json.dumps(report_dict))


if __name__ in "__main__":
    import sys
    print("Main")
    debug_files = [sys.argv[1]]
    load_debug_report(debug_files)
