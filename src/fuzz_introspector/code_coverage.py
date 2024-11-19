# Copyright 2022 Fuzz Introspector Authors
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
"""Module for handling code coverage reports"""

import os
import sys
import json
import logging
import re

from typing import (
    Any,
    Dict,
    List,
    Set,
    Optional,
    Tuple,
)

from fuzz_introspector import utils
from fuzz_introspector import exceptions

COVERAGE_SWITCH_REGEX = re.compile(r'.*\|.*\sswitch.*\(.*\)')
COVERAGE_CASE_REGEX = re.compile(r'.*\|.*\scase.*:')
COVERAGE_BRANCH_REGEX = re.compile(r'.*\|.*\sBranch.*\(.*:.*\):')

logger = logging.getLogger(name=__name__)


class CoverageProfile:
    """Stores and handles a runtime coverage data.

    :ivar Dict[str, List[Tuple[int, int]]] covmap:  Dictionary of string to
        list of tuples of ints. The tuples correspond to line number and
        hitcount. The string can have multiple meanings depending on the
        language being handled. For C/C++ it corresponds to functions,
        and for Python it correspond to source code files.

        If the key is file paths then `set_type` returns "file".

    :ivar Dict[str, List[Tuple[int, int]]] file_map: Dictionary holding
        mappings between source code files and line numbers and hitcounts.

    :ivar Dict[str, Tuple[int, int]] branch_cov_map: Dictionary to collect
        the branch coverage info in the form of current_func:line_number as
        the key and list of hitcounts as value.
    """

    def __init__(self) -> None:
        self.covmap: Dict[str, List[Tuple[int, int]]] = dict()
        self.file_map: Dict[str, List[Tuple[int, int]]] = dict()
        self.branch_cov_map: Dict[str, List[int]] = dict()
        self._cov_type = ""
        self.coverage_files: List[str] = []
        self.dual_file_map: Dict[str, Dict[str, List[int]]] = dict()
        self.kernel_coverage: List[Dict[Any, Any]] = []

    def set_type(self, cov_type: str) -> None:
        self._cov_type = cov_type

    def get_type(self) -> str:
        return self._cov_type

    def is_type_set(self) -> bool:
        return self._cov_type != ""

    def get_kernel_hitcount(self, node):
        try:
            target_file = node.parent_calltree_callsite.dst_function_source_file
        except Exception:
            return 0
        lineno = node.src_linenumber

        if target_file.startswith('../'):
            target_file = target_file[3:]

        for cov_module in self.kernel_coverage:
            if cov_module['Filename'].endswith(target_file):
                # Check if the line is hit
                for i in range(10):
                    if lineno + i in cov_module.get('Covered', []):
                        return 100
        return 0

    def is_file_lineno_hit(self,
                           target_file: str,
                           lineno: int,
                           resolve_name: bool = False) -> bool:
        """Checks if a given linenumber in a file is hit.

        :param target_file: file to inspect
        :type target_file: str

        :param lineno: line number in the file
        :type lineno: int

        :param resolve_name: whether to normalise name. This is only used
            for Python code coverage where the filename being tracked is
            extracted from a pyinstaller executable.
        :type resolve_name: bool

        :rtype: bool
        :returns: `True` if lineno is covered in the given soruce file. `False`
            otherwise.
        """
        logger.info(f"In generic hit -- {str(target_file)}")
        if self.get_type() != "file":
            logger.info("Failed to check hit")
            return False

        logger.debug("File type")
        target_key = target_file
        # Resolve name if required. This is needed to normalise filenames.
        if resolve_name:
            normalized_key = self._python_ast_funcname_to_cov_file(target_file)
            if normalized_key is None:
                return False
            target_key = normalized_key

        # Return False if file is not in file_map
        if target_key not in self.file_map:
            logger.debug("Target key is not in file_map")
            return False

        # Return True if lineno is in the relevant filemap value.
        if lineno in self.file_map[target_key]:
            logger.debug("Success")
            return True

        # Check if "fuzz" is in the filename. This is a hack in python coverage
        if "fuzz" in target_key:
            logger.debug("Checking adjustment")
            # 11 in the below code reflects the size of the coverage stub added here:
            # https://github.com/google/oss-fuzz/blob/360b484fa0f026c0dea44c62897519c6c99127cc/infra/base-images/base-builder/compile_python_fuzzer#L29-L40  # noqa: E501
            if lineno + 11 in self.file_map[target_key]:
                logger.debug("Success with line number adjustment")
                return True

        return False

    def is_func_hit(self, funcname: str) -> bool:
        """Returs whether a function is hit"""
        _, lines_hit = self.get_hit_summary(funcname)
        if lines_hit is not None and lines_hit > 0:
            return True
        return False

    def get_hit_details(self, funcname: str) -> List[Tuple[int, int]]:
        """Returns details of code coverage for a given function.

        This should only be used for coverage profiles that are non-file type.

        :param funcname: Function name to lookup.
        :type funcname: str

        :rtype: List[Tuple[int, int]]
        :returns: List of pairs where the first element is the source code
            linenumber and the second element is the amount of times that line
            was covered.
        """
        logger.debug(f"Getting coverage of {funcname}")
        fuzz_key = None
        if funcname in self.covmap:
            fuzz_key = funcname
        elif utils.demangle_cpp_func(funcname) in self.covmap:
            fuzz_key = utils.demangle_cpp_func(funcname)
        elif utils.normalise_str(funcname) in self.covmap:
            fuzz_key = utils.normalise_str(funcname)
        elif utils.remove_jvm_generics(funcname) in self.covmap:
            fuzz_key = utils.remove_jvm_generics(funcname)

        if fuzz_key is None or fuzz_key not in self.covmap:
            return []

        return self.covmap[fuzz_key]

    def _python_ast_funcname_to_cov_file(self, function_name) -> Optional[str]:
        """Convert a Python module path to a given file, and searches the
        file_map for whether this path exists in it.

        For example,

        mod_a.mod_b.func_1

        Is converted into:
        [ "/mod_a.py", "/mod_a/mod_b.py", "/mod_a/mod_b/func_1.py"] and then
        for each of those elements are searched whether any of those exist
        in the file_map. In the event one of the elements matches a file
        in the file_map then this file is returned.
        """
        function_name = function_name.replace("......", "")

        # Resolve name if required. This is needed to normalise filenames.
        logger.debug("Resolving name")
        potential_paths = []
        init_paths = []
        current_path = ""
        for module_name in function_name.split("."):
            current_path += module_name
            init_paths.append(current_path + "/__init__.py")
            potential_paths.append(current_path + ".py")
            current_path += "/"

        logger.debug(f"Potentials: {str(potential_paths)}")
        for potential_key in self.file_map:
            logger.debug(f"Scanning {str(potential_key)}")
            for potential_path in potential_paths:
                if potential_key.endswith(potential_path):
                    logger.debug(f"Found key: {str(potential_key)}")
                    return potential_key
        # We found no matches when filenames exclude __init__.py. Try to
        # include these now.
        init_matches = []
        # Iterate based in init paths since we want to have the longest match
        # at the end of __init__matches list.
        logger.info("Scanning for init paths")
        for potential_init_path in init_paths:
            logger.info("Trying %s", potential_init_path)
            for potential_key in self.file_map:
                logger.debug("Scanning %s", str(potential_key))
                if potential_key.endswith(potential_init_path):
                    logger.debug("Found __init__ match: %s",
                                 str(potential_key))
                    init_matches.append(potential_key)

        # Return the last match, as this signals the path with most precise
        # matching.
        if len(init_matches) > 0:
            return init_matches[-1]

        # If this is reached then no match was found. Return None.
        logger.debug("Could not find key")
        return None

    def _retrieve_func_line(
        self,
        file_and_function_mappings,
    ) -> Dict[str, List[Tuple[str, int, int]]]:
        # Sort function and lines numbers for each coverage file.
        # Store in function_internals.
        logger.debug("Geting function start and end line")
        function_internals: Dict[str, List[Tuple[str, int, int]]] = dict()
        for cov_file, function_specs in file_and_function_mappings.items():
            # Sort by line number
            sorted_func_specs = list(sorted(function_specs,
                                            key=lambda x: x[1]))

            function_internals[cov_file] = []
            for i in range(len(sorted_func_specs)):
                fname, fstart = sorted_func_specs[i]

                # Get next function lineno to identify boundary
                if i < len(sorted_func_specs) - 1:
                    fnext_name, fnext_start = sorted_func_specs[i + 1]
                    function_internals[cov_file].append(
                        (fname, fstart, fnext_start - 1))
                else:
                    # Last function identified by end lineno being -1
                    function_internals[cov_file].append((fname, fstart, -1))

        return function_internals

    def _map_func_covmap(
        self,
        function_internals,
    ) -> None:
        for filename in function_internals:
            logger.debug("Filename: %s", filename)
            for fname, fstart, fend in function_internals[filename]:
                logger.debug(f"--- {fname} ::: {fstart} ::: {fend}")

                if fname not in self.covmap:
                    # Fail safe
                    self.covmap[fname] = []

                # If we have the file in dual_file_map identify the
                # executed vs non-executed lines and store in covmap.
                if filename not in self.dual_file_map:
                    continue

                # Create the covmap
                for exec_line in self.dual_file_map[filename][
                        'executed_lines']:
                    if (exec_line > fstart) and (exec_line < fend
                                                 or fend == -1):
                        logger.debug("E: %s", exec_line)
                        self.covmap[fname].append((exec_line, 1000))
                for non_exec_line in self.dual_file_map[filename][
                        'missing_lines']:
                    if (non_exec_line > fstart) and (non_exec_line < fend
                                                     or fend == -1):
                        logger.debug("N: %s", non_exec_line)
                        self.covmap[fname].append((non_exec_line, 0))

    def correlate_python_functions_with_coverage(
        self,
        function_list,
    ) -> None:

        logger.info("Correlating")
        # For each function identified in the ast identify the file
        # where it resides in with respect to the filepaths from the
        # coverage collection. Store this including the linumber
        # of the function definition.
        file_and_function_mappings: Dict[str, List[Tuple[str, int]]] = dict()
        for func_key in function_list:
            func = function_list[func_key]
            function_name = func.function_name
            function_line = func.function_linenumber

            logger.debug(
                f"Correlated init: {function_name} ---- {function_line}")
            cov_file = self._python_ast_funcname_to_cov_file(function_name)
            if cov_file is None:
                continue

            # Return False if file is not in file_map
            if cov_file not in self.file_map:
                logger.debug("Target key is not in file_map")
                continue

            if cov_file not in file_and_function_mappings:
                file_and_function_mappings[cov_file] = []

            file_and_function_mappings[cov_file].append(
                (function_name, function_line))

        # Sort and retrieve line range of all functions
        function_internals = self._retrieve_func_line(
            file_and_function_mappings)

        # Map the source codes of each line with coverage information.
        # Store the result in covmap to be compatible with other languages.
        self._map_func_covmap(function_internals)

        return

    def get_hit_summary(self,
                        funcname: str) -> Tuple[Optional[int], Optional[int]]:
        """Returns the hit summary of a give function.

        This should only be used for coverage profiles that are non-file type.

        :param funcname: Function name to lookup.
        :type funcname: str

        :rtype: List[Tuple[Optional[int], Optional[int]]]
        :returns: List of pairs where the first element is
            the total amount of lines in a function and second element is the
            amount of lines in the function that are hit.
        """
        fuzz_key = None
        if funcname in self.covmap:
            fuzz_key = funcname
        elif utils.demangle_cpp_func(funcname) in self.covmap:
            fuzz_key = utils.demangle_cpp_func(funcname)
        elif utils.normalise_str(funcname) in self.covmap:
            fuzz_key = utils.normalise_str(funcname)
        elif utils.remove_jvm_generics(funcname) in self.covmap:
            fuzz_key = utils.remove_jvm_generics(funcname)

        if fuzz_key is None:
            return None, None

        lines_hit = [ht for ln, ht in self.covmap[fuzz_key] if ht > 0]
        return len(self.covmap[fuzz_key]), len(lines_hit)

    def is_func_lineno_hit(self, func_name: str, lineno: int) -> bool:
        """
        Checks if a given line number in a function is hit.
        """
        func_hit_details = self.get_hit_details(func_name)

        for line_info in func_hit_details:
            if lineno == line_info[0]:
                if line_info[1] != 0:
                    return True
                else:
                    return False
        return False


def extract_hitcount(coverage_line: str) -> int:
    """
    Extract the count from coverage format hitcount: 4.68k or 5.2M.
    The caller has to check for error returns before using the value.
    """
    coverage_line = coverage_line.strip()
    if len(coverage_line) == 0:
        return -1
    unit = coverage_line[-1]
    if not unit.isalpha():
        try:
            return int(coverage_line)
        except Exception:
            return -1

    if unit not in ['k', 'M', 'G']:
        logger.error(
            f'Unexpected coverage count unit: {unit} as in {coverage_line}')
        return -1
    num = float(coverage_line[:-1])
    if unit == 'k':
        num *= 1000
    elif unit == 'M':
        num *= 1000000
    elif unit == 'G':
        num *= 1000000000
    return int(num)


def load_llvm_coverage(target_dir: str,
                       target_name: Optional[str] = None) -> CoverageProfile:
    """
    Scans a directory to read one or more coverage reports, and returns a CoverageProfile

    Parses output from "llvm-cov show", e.g.
        llvm-cov show -instr-profile=$profdata_file -object=$target \
          -line-coverage-gt=0 $shared_libraries $LLVM_COV_COMMON_ARGS > \
          ${FUZZER_STATS_DIR}/$target.covreport

    This is used to parse C/C++ coverage.

    The function supports loading multiple and individual coverage reports.
    This is needed because finding coverage on a per-fuzzer basis requires
    correlating binary files to a specific introspection profile from compile time.
    However, files could be moved around, renamed, and so on.

    As such, this function accepts an arugment "target_name" which is used to
    target specific coverage profiles. However, if no coverage profile matches
    that given name then the function will find *all* coverage reports it can and
    use all of them.
    """

    if target_name is not None:
        logger.info(f"Loading LLVM coverage for target {target_name}")
    else:
        logger.info(f"Loading LLVM coverage for directory {target_dir}")

    all_coverage_reports = utils.get_all_files_in_tree_with_regex(
        target_dir, ".*\.covreport$")
    logger.info(f"Found {len(all_coverage_reports)} coverage reports")

    coverage_reports = list()

    # Only use coverage report for the target if there is one.
    if target_name is not None:
        for cov_report in all_coverage_reports:
            cov_report_base = os.path.basename(cov_report)
            if cov_report_base == target_name + ".covreport":
                coverage_reports.append(cov_report)

    # If we found no target coverage report then use all reports.
    if len(coverage_reports) == 0:
        coverage_reports = all_coverage_reports

    cp = CoverageProfile()
    logger.info(f"Using the following coverages {coverage_reports}")
    cp.set_type("function")
    for profile_file in coverage_reports:
        cp.coverage_files.append(profile_file)
        logger.info(f"Reading coverage report: {profile_file}")
        with open(profile_file, 'rb') as pf:
            curr_func = None
            switch_string = str()
            switch_line_number = None
            case_line_numbers: Set[int] = set()
            for raw_line in pf:
                line = utils.safe_decode(raw_line)
                if line is None:
                    continue

                line = line.replace("\n", "")
                logger.debug(f"cov-readline: { line }")

                # Parse lines that signal function names. These linse indicate that the
                # lines following this line will be the specific source code lines of
                # the given function.
                # Example line:
                #  "LLVMFuzzerTestOneInput:\n"
                if len(line) > 0 and line[-1] == ":" and "|" not in line:
                    if len(line.split(":")) == 3:
                        curr_func = line.split(":")[1].replace(" ",
                                                               "").replace(
                                                                   ":", "")
                    else:
                        curr_func = line.replace(" ", "").replace(":", "")
                    curr_func = utils.demangle_cpp_func(curr_func)
                    cp.covmap[curr_func] = list()
                    switch_string = ''
                    switch_line_number = None
                # Special treatment for switch statement coverage:
                # The line for switch MAY get one Branch entry; We use it for collecting
                # overall hitcout of statement.
                # Each `case` gets its own Branch entry for coverage. The important part
                # is true_hit because that means if a `case` is taken or not.
                if curr_func and COVERAGE_SWITCH_REGEX.match(line):
                    line_segs = line.split("|")
                    try:
                        switch_line_number = int(line_segs[0])
                    except Exception:
                        continue

                    try:
                        # Calculate the column of the switch keyword.
                        column_number = line_segs[2].find('switch') + 1
                    except Exception:
                        continue
                    case_line_numbers = set()  # To keep track of switch cases.
                    # This string may be updated if there is Branch pattern for this line.
                    switch_string = f'{curr_func}:{switch_line_number},{column_number}'
                    logger.debug(f'Seen switch in coverage: {switch_string}')

                # This parses Branch cov info in the form of:
                #  |  Branch (81:7): [True: 1.2k, False: 0]
                if curr_func and COVERAGE_BRANCH_REGEX.match(line):
                    try:
                        line_number = int(line.split('(')[1].split(':')[0])
                    except Exception:
                        continue
                    try:
                        column_number = int(line.split(':')[1].split(')')[0])
                    except Exception:
                        continue

                    try:
                        true_hit = extract_hitcount(
                            line.split('True:')[1].split(',')[0])
                        if true_hit == -1:
                            continue
                    except Exception:
                        continue
                    try:
                        false_hit = extract_hitcount(
                            line.split('False:')[1].replace("]", ""))
                        if false_hit == -1:
                            continue
                    except Exception:
                        continue

                    if switch_line_number and line_number == switch_line_number:
                        # This Branch pattern belongs to switch line.
                        # Note that the column number is inacurrate as it belongs to
                        # the variable inside pranthesis. Should not use it for switch_string.
                        cp.branch_cov_map[switch_string] = [
                            true_hit, false_hit
                        ]
                    elif line_number in case_line_numbers:
                        # This Branch pattern belongs to a `case`.
                        try:
                            # This collects for `case` taken side.
                            cp.branch_cov_map[switch_string].append(true_hit)
                        except Exception:
                            # Taking care of anomalies where the coverage report has no
                            # Branch pattern for switch line.
                            logger.debug(
                                f'The switch had no Branch pattern {switch_string}'
                            )
                            cp.branch_cov_map[switch_string] = [
                                true_hit, false_hit, true_hit
                            ]
                    else:
                        # This Branch pattern belongs to a conditional branch.
                        branch_string = f'{curr_func}:{line_number},{column_number}'
                        cp.branch_cov_map[branch_string] = [
                            true_hit, false_hit
                        ]
                # Parse lines that signal specific line of code. These lines only
                # offer after the function names parsed above.
                # Example line:
                #  "   83|  5.99M|    char *kldfj = (char*)malloc(123);\n"
                elif curr_func is not None and "|" in line:
                    # Extract source code line number
                    try:
                        line_number = int(line.split("|")[0])
                    except Exception:
                        continue

                    if COVERAGE_CASE_REGEX.match(line):
                        if switch_string:
                            case_line_numbers.add(line_number)
                        else:
                            logger.info('found case outside a switch?! \n%s',
                                        line)

                    # Extract hit count
                    # Write out numbers e.g. 1.2k into 1200 and 5.99M to 5990000
                    try:
                        hit_times = extract_hitcount(line.split("|")[1])
                        if hit_times == -1:
                            continue
                    except Exception:
                        # Avoid overcounting the code lines by skipping comments and empty lines.
                        if " 0| " in line:
                            hit_times = 0
                        else:
                            continue
                    # Add source code line and hitcount to coverage map of current function
                    logger.debug(f"reading coverage: {curr_func} "
                                 f"-- {line_number} -- {hit_times}")
                    cp.covmap[curr_func].append((line_number, hit_times))
    return cp


def load_python_json_coverage(json_file: str,
                              strip_pyinstaller_prefix: bool = True):
    """Loads a python json coverage file.

    The specific json file that is handled by the coverage output from:
    - https://coverage.readthedocs.io/en/latest/cmd.html#json-reporting-coverage-json

    Return a CoverageProfile
    """
    import json
    cp = CoverageProfile()
    cp.set_type("file")

    coverage_reports = utils.get_all_files_in_tree_with_regex(
        json_file, ".*all_cov.json$")
    logger.info(f"FOUND JSON FILES: {str(coverage_reports)}")

    if len(coverage_reports) > 0:
        json_file = coverage_reports[0]
    else:
        logger.info("Found no coverage files")
        return cp

    cp.coverage_files.append(json_file)
    with open(json_file, "r") as f:
        data = json.load(f)

    for entry in data['files']:
        cov_entry = entry

        # Strip any directories added by pyinstaller or oss-fuzz coverage handling
        if strip_pyinstaller_prefix:
            prefixed_entry = entry.replace("/pythoncovmergedfiles", "")
            prefixed_entry = prefixed_entry.replace("/medio", "")
            cov_entry = prefixed_entry
        cp.file_map[cov_entry] = data['files'][entry]['executed_lines']
        cp.dual_file_map[cov_entry] = dict()
        cp.dual_file_map[cov_entry]['executed_lines'] = data['files'][entry][
            'executed_lines']
        cp.dual_file_map[cov_entry]['missing_lines'] = data['files'][entry][
            'missing_lines']
    return cp


def load_jvm_coverage(target_dir: str,
                      target_name: Optional[str] = None) -> CoverageProfile:
    """Find and load jacoco.xml, a jvm xml coverage report file

    The xml file is generated from Jacoco plugin. The specific dtd of the xml can
    be found in the following link:
    - https://www.jacoco.org/jacoco/trunk/coverage/report.dtd

    Return a CoverageProfile
    """
    import xml.etree.ElementTree as ET
    cp = CoverageProfile()
    cp.set_type("function")

    # Retrieve jacoco.xml coverage report
    coverage_reports = utils.get_all_files_in_tree_with_regex(
        target_dir, "jacoco.xml")
    logger.info(f"FOUND XML COVERAGE FILES: {str(coverage_reports)}")

    if len(coverage_reports) > 0:
        xml_file = coverage_reports[0]
    else:
        logger.info("Found no coverage files")
        return cp

    # Parse the jacoco.xml to element tree
    cp.coverage_files.append(xml_file)
    try:
        xml_tree = ET.parse(xml_file)
        root = xml_tree.getroot()
    except Exception:
        raise exceptions.DataLoaderError("Error %s as xml file" % (xml_file))

    # Handles package by package
    for package in root.findall('package'):
        # Extract all source lines mapping
        # In jacoco.xml, each packages contains a list of source files and classes.
        # In each of the source file tag, it contains a list of line child elements
        # for each valid line in that source file with the count of runtime coverage
        # of that line. This information is separated with the methods and thus we
        # are extracting them as a map for further reference when processing all
        # the methods.
        source_file_map = {}
        for src in package.findall('sourcefile'):
            line_list = []
            for line in src.findall('line'):
                # Process each line
                line_list.append(
                    (int(line.attrib['nr']), int(line.attrib['ci'])))
            if line_list:
                source_file_map[src.attrib["name"]] = line_list

        # Process all methods in all classes within this package
        for cl in package.findall('class'):
            class_name = cl.attrib.get('name', '').replace('/', '.')
            line_list = source_file_map.get(
                cl.attrib.get('sourcefilename', ''), [])
            if not class_name or not line_list:
                # Fail safe for malformed or invalid jacoco.xml report or
                # no source file found because target class not compiled
                # with correct debug information.
                continue

            for method in cl.findall('method'):
                # Determine method full signaturre
                name = method.attrib.get('name', '')
                desc = method.attrib.get('desc', '')
                start_line = int(method.attrib.get('line', '-1'))

                if not name or not desc or start_line < 0:
                    # Fail safe for malformed or invalid jacoco.xml report with
                    # no line number information.
                    continue

                args = _interpret_jvm_arguments_type(desc)
                name = f'[{class_name}].{method.attrib["name"]}({",".join(args)})'

                # Get total valid lines count of this method
                total_line = 0
                for counter in method.findall('counter'):
                    if counter.attrib['type'] == 'LINE':
                        missed_line = int(counter.attrib['missed'])
                        covered_line = int(counter.attrib['covered'])
                        total_line = missed_line + covered_line
                        break

                # Find the starting item in the line map
                start_item = -1
                for count, item in enumerate(line_list):
                    if item[0] == start_line:
                        start_item = count
                        break

                # if starting item not found, skip this method
                if start_item < 0:
                    continue

                # Find the ending item in the line map
                end_item = min(start_item + total_line, len(line_list))

                # Store lines, hit_time into the covmap under the target method
                cp.covmap[name] = []
                # Add source code line and hitcount to coverage map of current function
                logger.debug(f"reading coverage: {name} -- {line_list[count]}")
                for count in range(start_item, end_item):
                    cp.covmap[name].append(line_list[count])

    return cp


def _interpret_jvm_arguments_type(desc: str) -> List[str]:
    """
      Interpret list of jvm arguments type for each method.
      The desc tag for each jvm method in the jacoco.xml coverage
      report is in basic Java class name specification following
      the format of "({Arguments}){ReturnType}". The basic java
      class name specification use single upper case letter for
      primitive types (and void type) and L{full_class_name}; for
      object arguments. The JVM_CLASS_MAPPING give the mapping of
      the single upper case letter of each primitive types.
      Arrays are specified with a [ character before the arugment
      type. The number of [ character determine the dimention of
      the array.
      For example, for a method
      "public void test(String,int,String[][],boolean[],int...)"
      The desc value of the above method will be
      "(Ljava.lang.String;I[[Ljava.lang.String;[Z[I)V".
      This method is necessary to match the full method name with
      the one given in the jacoco.xml report with full argument list.
    """
    JVM_CLASS_MAPPING = {
        'Z': 'boolean',
        'B': 'byte',
        'C': 'char',
        'D': 'double',
        'F': 'float',
        'I': 'int',
        'J': 'long',
        'S': 'short'
    }

    # Extract arguments and remove return value from description
    desc = desc.split('(', 1)[1].split(')', 1)[0]

    args = []
    arg = ''
    start = False
    next_arg = ''
    array_count = 0
    for c in desc:
        if c == '(':
            continue
        if c == ')':
            break

        if start:
            if c == ';':
                start = False
                next_arg = arg.replace('/', '.')
            else:
                arg = arg + c
        else:
            if c == 'L':
                start = True
                if next_arg:
                    next_arg = f'{next_arg}{"[]" * array_count}'
                    array_count = 0
                    args.append(next_arg)
                arg = ''
                next_arg = ''
            elif c == '[':
                array_count += 1
            else:
                if c in JVM_CLASS_MAPPING:
                    if next_arg:
                        next_arg = f'{next_arg}{"[]" * array_count}'
                        array_count = 0
                        args.append(next_arg)
                    next_arg = JVM_CLASS_MAPPING[c]

    if next_arg:
        next_arg = f'{next_arg}{"[]" * array_count}'
        args.append(next_arg)
    return args


def load_kernel_cov(filename):
    """Loads a .json code coverage file from Syzkaller."""
    print('Loading kernel coverage')
    with open(filename, 'r') as f:
        json_coverage = json.loads(f.read())

    private_modules = []
    for elem in json_coverage:
        if '/private/' in elem.get('Filename', ''):
            private_modules.append(elem)

    cp = CoverageProfile()
    cp.set_type('kernel')
    cp.kernel_coverage = private_modules
    return cp


if __name__ == "__main__":
    logging.basicConfig()
    logger.info("Starting coverage loader")
    load_kernel_cov(sys.argv[1])
