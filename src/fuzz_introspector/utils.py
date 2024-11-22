# Copyright 2021 Fuzz Introspector Authors
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
""" Utility functions """

import cxxfilt
import rust_demangler
import logging
import json
import os
import re
import shutil
import yaml

from typing import (
    Any,
    List,
    Dict,
    Optional,
    Set,
    Tuple,
)

from fuzz_introspector import constants

logger = logging.getLogger(name=__name__)


def longest_common_prefix(strs: List[str]) -> str:
    """
    Dummy wrapper function for os.path.commonpath(paths: List[str]) -> str
    Keeping for backward compactibility
    """
    try:
        return os.path.commonpath(strs)
    except ValueError:
        return '/'


def normalise_str(s1: str) -> str:
    return s1.replace("\t", "").replace("\r", "").replace("\n",
                                                          "").replace(" ", "")


def safe_decode(data) -> Optional[str]:
    try:
        return data.decode()
    except Exception:
        None
    try:
        return data.decode('unicode-escape')
    except Exception:
        None
    return None


def get_all_files_in_tree_with_regex(basedir: str,
                                     regex_str: str) -> List[str]:
    """
    Returns a list of paths such that each path is to a file with
    the provided suffix. Walks the entire tree of basedir.
    """
    r = re.compile(regex_str)
    data_files = []
    for root, dirs, files in os.walk(basedir):
        for f in files:
            if r.match(f):
                data_files.append(os.path.join(root, f))
    return data_files


def data_file_read_yaml(filename: str) -> Optional[Dict[Any, Any]]:
    """
    Reads a file as a yaml file. This is used to load data
    from fuzz-introspectors compiler plugin output.
    """
    if filename == "":
        return None
    if not os.path.isfile(filename):
        return None

    try:
        yaml.SafeLoader = yaml.CSafeLoader  # type: ignore[assignment, misc]
        logger.info("Set base loader to use CSafeLoader")
    except Exception:
        logger.info("Could not set CSafeLoader as base loader")

    try:
        with open(filename, 'r') as stream:
            data_dict: Dict[Any, Any] = yaml.safe_load(stream)
            logger.info("Loaded single yaml module")
            return data_dict
    except Exception:
        # YAML library does not completely wrap exceptions, so unless
        # we catch all exceptions here we might end up in a crashing state.
        # This likely fails as the LLVM frontend now is putting multiple docs in
        # same yaml file. See commit 737ba72.
        pass

    # Try loading multiple yaml files in the fuzz introspector format
    # We need this because we have different formats for each language.
    logger.info("Trying to load multiple file formats together.")
    try:
        with open(filename, 'r') as yaml_f:
            data = yaml_f.read()
            docs = yaml.safe_load_all(data)
    except Exception as e:
        # YAML library does not completely wrap exceptions, so unless
        # we catch all exceptions here we might end up in a crashing state.
        logger.info("Failed loading YAML: " + str(e))
        return None

    content = dict()
    try:
        for doc in docs:
            if not doc or not isinstance(doc, dict):
                return None
            if "Fuzzer filename" in doc and "Fuzzer filename" not in content:
                content["Fuzzer filename"] = doc["Fuzzer filename"]
            if "All functions" in doc:
                if "All functions" not in content:
                    content['All functions'] = doc['All functions']
                else:
                    content['All functions']['Elements'].extend(
                        doc['All functions']['Elements'])
    except Exception as e:
        # YAML library does not completely wrap exceptions, so unless
        # we catch all exceptions here we might end up in a crashing state.
        logger.info("Failed loading YAML: " + str(e))
        return None

    if "Fuzzer filename" not in content:
        return None
    if "All functions" not in content:
        return None
    return content


def demangle_cpp_func(funcname: str) -> str:
    try:
        demangled: str = cxxfilt.demangle(funcname.replace(" ", ""))
        return demangled
    except Exception:
        return funcname


def demangle_rust_func(funcname: str) -> str:
    # Ignore all non-mangled rust function names
    # All mangled rust function names started with _R
    if not funcname.startswith("_R"):
        return funcname

    try:
        demangled: str = rust_demangler.demangle(funcname.replace(" ", ""))
        demangled = demangled.replace('<', '').replace('>', '')
        return demangled
    except Exception:
        return funcname


def demangle_jvm_func(package: str, funcname: str) -> str:
    """Add package class name to uniquly identify jvm functons"""
    if funcname.startswith("["):
        return funcname
    else:
        return "[%s].%s" % (package, funcname)


def remove_jvm_generics(funcname: str) -> str:
    """Remove generic arguments from the full jvm method name."""
    pattern = r'<[\s.,a-zA-Z0-9]+>|\\u003C[\s.,a-zA-Z0-9]+\\u003E'
    return re.sub(pattern, '', funcname)


def scan_executables_for_fuzz_introspector_logs(
        exec_dir: str) -> List[Dict[str, str]]:
    """Finds all executables containing fuzzerLogFile string

    Args:
        exec_dir: Directory in which to search for executables.

    Returns:
        A list of dictionaries where each dictionary contains data about
        an executable that contains fuzzerLogFile string.
    """
    if not os.path.isdir(exec_dir):
        return []

    # Find all executables
    executable_files = []
    for f in os.listdir(exec_dir):
        full_path = os.path.join(exec_dir, f)
        if os.access(full_path, os.X_OK) and os.path.isfile(full_path):
            logger.info("File: %s is executable" % full_path)
            executable_files.append(full_path)

    # Filter all executables containing "fuzzerLogFile" string
    executable_to_fuzz_reports = []
    text_pattern = re.compile("[A-Za-z0-9_-]{10,}")
    for executable_path in executable_files:
        with open(executable_path, "rb") as fp:
            all_ascii_data = fp.read().decode('ascii', 'ignore')

        # Check if file contains fuzzerLogFile string
        for re_match in text_pattern.finditer(all_ascii_data):
            found_str = re_match.group(0)
            if "fuzzerLogFile" not in found_str:
                continue
            logger.info("Found match %s" % found_str)
            executable_to_fuzz_reports.append({
                'executable_path': executable_path,
                'fuzzer_log_file': found_str
            })
            # Break when a string is found to avoid scanning the whole binary.
            break

    return executable_to_fuzz_reports


def approximate_python_coverage_files_list(
        src1: str,
        possible_targets: List[Tuple[str, str]],
        resolve_inits=False) -> Optional[str]:
    # Remove prefixed .....
    src1 = src1.lstrip(".")

    # Generate list of potential candidates
    possible_candidates = []
    possible_init_candidates = []
    splits = src1.split(".")
    curr_str = ""
    for s2 in splits:
        curr_str = curr_str + s2
        possible_candidates.append(curr_str + ".py")
        possible_init_candidates.append(curr_str + "/__init__.py")
        curr_str = curr_str + "/"
    logger.debug("[%s] -- Created init candidates: %s" %
                 (src1, str(possible_init_candidates)))

    # Start from backwards to find te longest possible candidate
    for candidate in reversed(possible_candidates):
        for fl, src2 in possible_targets:
            if src2.endswith(candidate):
                # ensure the entire filename is matched in the event of not slashes
                if "/" not in candidate:
                    if not src2.split("/")[-1] == candidate:
                        continue
                logger.debug("Found target: %s" % (candidate))
                return fl

    # Will only get to hear if none of the above candidates matched. This
    # means the match is either in an __init__.py file or there is no match.
    if resolve_inits:
        for init_candidate in reversed(possible_init_candidates):
            for fl, src2 in possible_targets:
                if src2.endswith(init_candidate):
                    # ensure the entire filename is matched in the event of not slashes
                    if "/" not in init_candidate:
                        if not src2.split("/")[-1] == init_candidate:
                            continue
                    logger.debug("Found target: %s" % (init_candidate))
                    return fl
    logger.debug("Could not find target")
    return None


def get_target_coverage_url(coverage_url: str, target_name: str,
                            target_lang: str) -> str:
    """
    This function changes overall coverage URL to per-target coverage URL. Like:
        https://storage.googleapis.com/oss-fuzz-coverage/<project>/reports/<report-date>/linux
        to
        https://storage.googleapis.com/oss-fuzz-coverage/<project>/reports-by-target/<report-date>/<target-name>/linux
    """
    logger.info(f"Extracting coverage for {coverage_url} -- {target_name}")
    if os.environ.get('FUZZ_INTROSPECTOR'):
        if target_lang == "c-cpp":
            return coverage_url.replace("reports",
                                        "reports-by-target").replace(
                                            "/linux", f"/{target_name}/linux")
        elif target_lang == "python":
            # TODO ADD python coverage link
            return coverage_url
        elif target_lang == "jvm":
            # TODO Add jvm coverage link
            return coverage_url
    # (TODO) This is temporary for local runs.
    return coverage_url


def load_func_names(input_list: List[str],
                    check_for_blocking: bool = True) -> List[str]:
    """
    Takes a list of function names (typically from llvm profile)
    and makes sure the output names are demangled.
    """
    loaded = []
    for reached in input_list:
        if (check_for_blocking
                and constants.BLOCKLISTED_FUNCTION_NAMES.match(reached)):
            continue
        loaded.append(demangle_rust_func(demangle_cpp_func(reached)))
    return loaded


def resolve_coverage_link(cov_url: str, source_file: str, lineno: int,
                          function_name: str, target_lang: str) -> str:
    """Resolves link to HTML coverage report"""
    result = "#"
    if (target_lang == "c-cpp" or target_lang == "rust"):
        result = source_file + ".html#L" + str(lineno)
    elif (target_lang == "python"):
        """Resolves link to HTML coverage report for Python targets"""
        # Temporarily for debugging purposes. TODO: David remove this later
        # Find the html_status.json file. This is a file generated by the Python
        # coverate utility and contains mappings from source to html file. We
        # need this mapping in order to create links from the data extracted
        # during AST analysis, as there we only have the source code.
        html_summaries = get_all_files_in_tree_with_regex(
            ".", ".*html_status.json$")
        logger.debug(str(html_summaries))
        if len(html_summaries) > 0:
            html_idx = html_summaries[0]
            with open(html_idx, "r") as jf:
                data = json.load(jf)
            possible_targets = []
            for fl in data['files']:
                possible_targets.append(
                    (fl, data['files'][fl]['index']['relative_filename']))

            found_target = approximate_python_coverage_files_list(
                function_name, possible_targets, True)
            if found_target is not None:
                result = found_target + ".html" + "#t" + str(lineno)
        else:
            logger.info("Could not find any html_status.json file")
    elif (target_lang == "jvm"):
        """Resolves link to HTML coverage report for JVM targets"""
        # Handle source class for jvm
        if ("." in source_file):
            # Source file has package, change package.class to package/class
            source_file = os.sep.join(source_file.rsplit(".", 1))
        else:
            # Source file has no package, add in default package
            source_file = os.path.join("default", source_file)

        # Handle subclass definition in the same source file
        source_file = source_file.split("$")[0]

        result = source_file + ".java.html#L" + str(lineno)
    else:
        logger.info("Unsupported language for coverage link resolve")

    if result != "#":
        result = cov_url.rstrip("/") + "/" + result.lstrip("/")

    return result


def group_path_list_by_target(list: List[List[Any]]) -> Dict[Any, List[Any]]:
    """
    Group path list items by path target which is
    the last itme of each list.
    """
    result_dict: Dict[Any, List[Any]] = {}
    for item in list:
        if len(item) == 0:
            continue
        if item[-1] in result_dict.keys():
            item_list = result_dict[item[-1]]
        else:
            item_list = []

        item_list.append(item)
        result_dict[item[-1]] = item_list

    return result_dict


def check_coverage_link_existence(link: str) -> bool:
    link = link.split("#")[0]
    if link.startswith("/"):
        link = link[1:]
    return os.path.exists(link) and os.path.isfile(link)


def _find_all_source_path(extension: str) -> Set[str]:
    """Search the $OUT/$SRC directory to find paths of all Java source files."""
    # Use set to avoid duplication
    source_path_list = set()

    # Retrieve $OUT and $SRC from environment variables
    out_dir = os.environ.get('OUT', None)
    src_dir = os.environ.get('SRC', None)
    logger.info(f'{out_dir}/{src_dir}')
    if out_dir and src_dir:
        # OSS-Fuzz store the source code in $OUT/$SRC directory
        path_to_search = os.path.join(out_dir, src_dir)
        if os.path.isdir(path_to_search):
            # Confirm that the source directory does exist
            for root, dirs, files in os.walk(path_to_search):
                if '/.' in root:
                    # Skipping hidden directory
                    continue
                for file in files:
                    if file.endswith(extension):
                        source_path_list.add(os.path.join(root, file))

    return source_path_list


def _copy_java_source_files(required_class_list: List[str]):
    """Copy the needed java source files."""
    logger.info(
        f'Copying java source files to {constants.SAVED_SOURCE_FOLDER}')

    count = 0
    java_source_path_set = _find_all_source_path('.java')

    copied_source_path_list = []
    for required_class in set(required_class_list):
        # Remove inner class name
        required_file = required_class.split('$', 1)[0]

        # Transform class name to java source file name
        if not required_file.endswith('.java'):
            required_file = f'{required_file.replace(".", "/")}.java'

        for java_source_path in java_source_path_set:
            if java_source_path.endswith(required_file):
                # Source file for the target class found. Copy it to the
                # SAVED_SOURCE_FOLDER while preserving package directories
                # of the target source file.
                dst = os.path.join(constants.SAVED_SOURCE_FOLDER,
                                   required_file)
                if os.path.isfile(dst):
                    # Skip duplicate files
                    continue
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                shutil.copy(java_source_path, dst)
                count += 1
                copied_source_path_list.append(required_file)
                break

    # Store a list of existing source file paths for reference
    with open(os.path.join(constants.SAVED_SOURCE_FOLDER, 'index.json'),
              'w') as f:
        f.write(json.dumps(copied_source_path_list))

    logger.info(
        f'Copied {count} java source files to {constants.SAVED_SOURCE_FOLDER}')


def _copy_python_source_files():
    """Copy the needed python source files."""
    logger.info(
        f'Copying python source files to {constants.SAVED_SOURCE_FOLDER}')

    count = 0
    python_source_path_set = _find_all_source_path('.py')
    os.makedirs(constants.SAVED_SOURCE_FOLDER, exist_ok=True)

    copied_source_path_list = []
    for python_source_path in python_source_path_set:
        filename = os.path.basename(python_source_path)
        dst = os.path.join(constants.SAVED_SOURCE_FOLDER, filename)

        if os.path.isfile(dst):
            # Skip duplicate files
            continue

        shutil.copy(python_source_path, dst)
        count += 1
        copied_source_path_list.append(filename)

    # Store a list of existing source file paths for reference
    with open(os.path.join(constants.SAVED_SOURCE_FOLDER, 'index.json'),
              'w') as f:
        f.write(json.dumps(copied_source_path_list))

    logger.info(
        f'Copied {count} python source files to {constants.SAVED_SOURCE_FOLDER}'
    )


def copy_source_files(required_class_list: List[str], language: str):
    """Copy the needed source files for different project.
    Currently only support Python and Java projects."""

    if language == 'jvm':
        _copy_java_source_files(required_class_list)
    elif language == 'python':
        _copy_python_source_files()
    else:
        logger.warning(
            f'Language: {language} not support. Skipping source file copy.')


def locate_rust_fuzz_key(funcname: str, map: Dict[str, Any]) -> Optional[str]:
    """Helper method for locating rust fuzz key with missing crate information."""

    while funcname:
        match = next((key for key in map if key.endswith(funcname)), None)
        # Ensure the matched key contains crate information which is unique for rust
        if match and "::" in match:
            return match

        if '::' in funcname:
            funcname = funcname.split('::', 1)[1]
        else:
            break

    return None


def locate_rust_fuzz_item(funcname: str, item_list: List[str]) -> str:
    """Helper method for locating str item with missing crate information."""

    if funcname in item_list:
        return funcname

    while funcname:
        for item in item_list:
            if item.endswith(funcname) and "::" in item:
                return item

        if '::' in funcname:
            funcname = funcname.split('::', 1)[1]
        else:
            break

    return ''
