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
import yaml

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
    # Place this import here because it makes it easier to run this module
    # as a main module.
    from fuzz_introspector import constants
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


def load_debug_all_yaml_files(debug_all_types_files):
    elem_list = []
    try:
        yaml.SafeLoader = yaml.CSafeLoader  # type: ignore[assignment, misc]
        logger.info("Set base loader to use CSafeLoader")
    except Exception:
        logger.info("Could not set the CSafeLoader as base loader")

    for filename in debug_all_types_files:
        with open(filename, 'r') as yaml_f:
            file_list = yaml.safe_load(yaml_f.read())
            elem_list += file_list
    return elem_list


def extract_func_sig_friendly_type_tags(target_type, debug_type_dictionary):
    """Recursively iterates atomic type elements to construct a friendly
    string representing the type."""
    if int(target_type) == 0:
        return ['void']

    tags = []
    type_to_query = target_type
    addresses_visited = set()
    while True:
        if type_to_query in addresses_visited:
            tags.append("Infinite loop")
            break

        target_type = debug_type_dictionary.get(int(type_to_query), None)
        if target_type is None:
            tags.append("N/A")
            break

        # Provide the tag
        tags.append(target_type['tag'])

        name = target_type.get("name", "")
        if name != "":
            tags.append(name)
            break

        base_type_string = target_type.get("base_type_string", "")
        if base_type_string != "":
            tags.append(base_type_string)
            break

        addresses_visited.add(type_to_query)

        type_to_query = target_type.get('base_type_addr', '')
        if int(type_to_query) == 0:
            tags.append("void")
            break

    return tags


def extract_debugged_function_signature(dfunc, debug_type_dictionary):
    """Extract the raw types used by a function."""
    try:
        return_type = extract_func_sig_friendly_type_tags(
            dfunc['type_arguments'][0], debug_type_dictionary)
    except IndexError:
        return_type = 'N/A'
    params = []

    if len(dfunc['type_arguments']) > 1:
        for i in range(1, len(dfunc['type_arguments'])):
            params.append(
                extract_func_sig_friendly_type_tags(dfunc['type_arguments'][i],
                                                    debug_type_dictionary))

    source_file = dfunc['file_location'].split(":")[0]
    try:
        source_line = dfunc['file_location'].split(":")[1]
    except IndexError:
        source_line = "-1"

    function_signature_elements = {
        'return_type': return_type,
        'params': params,
    }
    source_location = {'source_file': source_file, 'source_line': source_line}

    return function_signature_elements, source_location


def convert_param_list_to_str_v2(param_list):
    pre = ""
    med = ""
    post = ""
    for param in param_list:
        if param == "DW_TAG_pointer_type":
            post += "*"
        elif param == 'DW_TAG_reference_type':
            post += '&'
        elif param == 'DW_TAG_structure_type':
            med += " struct "
            continue
        elif param == "DW_TAG_base_type":
            continue
        elif param == "DW_TAG_typedef":
            continue
        elif param == 'DW_TAG_class_type':
            continue
        elif param == "DW_TAG_const_type":
            pre += "const "
        elif param == "DW_TAG_enumeration_type":
            continue
        else:
            med += str(param)

    raw_sig = pre.strip() + " " + med + " " + post
    return raw_sig.strip()


def is_struct(param_list):
    for param in param_list:
        if param == 'DW_TAG_structure_type':
            return True
    return False


def is_enumeration(param_list):
    for param in param_list:
        if param == 'DW_TAG_enumeration_type':
            return True
    return False


def create_friendly_debug_types(debug_type_dictionary):
    """Create an address-indexed json dictionary. The goal is to use this for
    fast iteration over types using e.g. recursive lookups."""
    friendly_name_sig = dict()
    logging.info("Have to create for %d addresses" %
                 (len(debug_type_dictionary)))
    idx = 0

    addr_members = dict()
    for elem_addr, elem_val in debug_type_dictionary.items():
        if elem_val['tag'] == "DW_TAG_member":
            current_members = addr_members.get(int(elem_val['scope']), [])
            elem_dict = {
                'addr':
                elem_addr,
                'elem_name':
                elem_val['name'],
                'elem_friendly_type':
                convert_param_list_to_str_v2(
                    extract_func_sig_friendly_type_tags(
                        elem_val['base_type_addr'], debug_type_dictionary))
            }
            current_members.append(elem_dict)
            addr_members[int(elem_val['scope'])] = current_members

    for addr in debug_type_dictionary:
        idx += 1
        if idx % 2500 == 0:
            logging.info("Idx: %d" % (idx))
        friendly_type = extract_func_sig_friendly_type_tags(
            addr, debug_type_dictionary)

        # is this a struct?
        # Collect elements
        structure_elems = []
        if is_struct(friendly_type):
            structure_elems = addr_members.get(int(addr), [])

        friendly_name_sig[addr] = {
            'raw_debug_info': debug_type_dictionary[addr],
            'friendly-info': {
                'raw-types': friendly_type,
                'string_type': convert_param_list_to_str_v2(friendly_type),
                'is-struct': is_struct(friendly_type),
                'struct-elems': structure_elems,
                'is-enum': is_enumeration(friendly_type),
                'enum-elems':
                debug_type_dictionary[addr].get('enum_elems', [])
            }
        }

    with open("all-friendly-debug-types.json", "w") as f:
        json.dump(friendly_name_sig, f)


def correlate_debugged_function_to_debug_types(all_debug_types,
                                               all_debug_functions):
    """Correlate debug information about all functions and all types. The
    result is a lot of atomic debug-information-extracted types are correlated
    to the debug function."""
    print("Correlating")

    # Index debug types by address. We need to do a lot of look ups when
    # refining data types where the address is the key, so a fast
    # look-up mechanism is useful here.
    debug_type_dictionary = dict()
    for debug_type in all_debug_types:
        debug_type_dictionary[int(debug_type['addr'])] = debug_type

    # Create json file with addresses as indexes for type information.
    # This can be used to lookup types fast.
    logger.info("Creating dictionary")
    create_friendly_debug_types(debug_type_dictionary)
    logger.info("Finished creating dictionary")

    for dfunc in all_debug_functions:
        func_signature_elems, source_location = extract_debugged_function_signature(
            dfunc, debug_type_dictionary)

        dfunc['func_signature_elems'] = func_signature_elems
        dfunc['source'] = source_location


def extract_syzkaller_type(param_list):
    """Converts the dwarf tag list to a syzkaller type."""
    pre = ""
    med = ""
    post = ""
    syzkaller_tag = ""
    for param in reversed(param_list):
        if param == "DW_TAG_pointer_type":
            syzkaller_tag = 'ptr [in, %s]' % (syzkaller_tag)
        elif param == 'DW_TAG_reference_type':
            post += '&'
        elif param == 'DW_TAG_structure_type':
            continue
        elif param == "DW_TAG_base_type":
            continue
        elif param == "DW_TAG_typedef":
            continue
        elif param == 'DW_TAG_class_type':
            continue
        elif param == "DW_TAG_const_type":
            pre += "const "
        elif param == "DW_TAG_enumeration_type":
            continue
        else:
            # This is a type and we should convert it to the syzkaller type
            if param == 'char':
                syzkaller_tag = 'int8'
            elif param == 'int':
                syzkaller_tag = 'int32'
            elif param == '__i32':
                syzkaller_tag = 'int32'
            elif param == '__u32' or param == 'u32':
                syzkaller_tag = 'int32'
            elif param == '__s32' or param == 's32':
                syzkaller_tag = 'int32'
            elif param == '__u64' or param == 's64':
                syzkaller_tag = 'int64'
            elif param == '__u8' or param == 'u8':
                syzkaller_tag = 'int8'
            elif param == '__u16' or param == 'u16':
                syzkaller_tag = 'int16'
            else:
                # This is a struct, so we name it appropriately
                syzkaller_tag = param

            med += str(param)

    return syzkaller_tag


def get_struct_members(addr, debug_type_dictionary):
    structure_elems = []
    for elem_addr, elem_val in debug_type_dictionary.items():
        if elem_val['tag'] == "DW_TAG_member" and int(
                elem_val['scope']) == int(addr):

            friendly_type = extract_func_sig_friendly_type_tags(
                elem_val['base_type_addr'], debug_type_dictionary)
            print("name: %s" % (elem_val['name']))
            print(friendly_type)
            print(convert_param_list_to_str_v2(friendly_type))

            syzkaller_type = extract_syzkaller_type(friendly_type)

            elem_dict = {
                'addr':
                elem_addr,
                'syzkaller_type':
                syzkaller_type,
                'elem_name':
                elem_val['name'],
                'raw':
                elem_val,
                'elem_friendly_type':
                convert_param_list_to_str_v2(
                    extract_func_sig_friendly_type_tags(
                        elem_val['base_type_addr'], debug_type_dictionary)),
                'friendly-info': {
                    'raw-types': friendly_type,
                    'string_type': convert_param_list_to_str_v2(friendly_type),
                    'is-struct': is_struct(friendly_type),
                    'is-enum': is_enumeration(friendly_type),
                }
            }
            structure_elems.append(elem_dict)
    return structure_elems


def create_syzkaller_description_for_type(addr, debug_type_dictionary):
    friendly_type = extract_func_sig_friendly_type_tags(
        addr, debug_type_dictionary)

    if is_struct(friendly_type):
        members = get_struct_members(addr, debug_type_dictionary)
        if len(members) == 0:
            return None

        syzkaller_description = "%s {\n" % (friendly_type[-1])
        for struct_mem in members:
            syzkaller_description += ' ' * 2 + "{0: <25}".format(
                struct_mem['elem_name'])
            syzkaller_description += ' ' * 4
            syzkaller_description += struct_mem['syzkaller_type']
            syzkaller_description += '\n'
        syzkaller_description += '}'
        return syzkaller_description
    if is_enumeration(friendly_type):
        raw_debug_type = debug_type_dictionary[addr]
        enum_type = "%s = %s" % (raw_debug_type['name'], ', '.join(
            raw_debug_type['enum_elems']))
        return enum_type

    return None


def syzkaller_get_struct_type_elems(typename, all_debug_types):
    debug_type_dictionary = dict()
    for debug_type in all_debug_types:
        debug_type_dictionary[int(debug_type['addr'])] = debug_type

    for debug_addr, debug_type in debug_type_dictionary.items():
        if debug_type['name'] == typename:
            friendly_type = extract_func_sig_friendly_type_tags(
                debug_addr, debug_type_dictionary)

            if is_struct(friendly_type):
                members = get_struct_members(debug_addr, debug_type_dictionary)
                return members

    return None


def syzkaller_get_type_implementation(typename, all_debug_types):
    # Index debug types by address. We need to do a lot of look ups when
    # refining data types where the address is the key, so a fast
    # look-up mechanism is useful here.
    debug_type_dictionary = dict()
    for debug_type in all_debug_types:
        debug_type_dictionary[int(debug_type['addr'])] = debug_type

    for debug_addr, debug_type in debug_type_dictionary.items():
        if debug_type['name'] == typename:
            syzkaller_description = create_syzkaller_description_for_type(
                debug_addr, debug_type_dictionary)
            if syzkaller_description:
                print('-' * 45)
                print(syzkaller_description)
                return syzkaller_description
    return None


if __name__ in "__main__":
    import sys
    type_debug_files = [sys.argv[1]]
    typename = sys.argv[2]

    all_types = load_debug_all_yaml_files(type_debug_files)
    syzkaller_get_type_implementation(typename, all_types)
