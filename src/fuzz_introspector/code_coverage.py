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

import logging

from typing import (
    Dict,
    List,
    Optional,
    Tuple,
)

from fuzz_introspector import utils

logger = logging.getLogger(name=__name__)
logger.setLevel(logging.INFO)


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
        the key and true_hit and false_hit as a tuple value.
    """
    def __init__(self) -> None:
        self.covmap: Dict[str, List[Tuple[int, int]]] = dict()
        self.file_map: Dict[str, List[Tuple[int, int]]] = dict()
        self.branch_cov_map: Dict[str, Tuple[int, int]] = dict()
        self._cov_type = ""

    def set_type(self, cov_type: str) -> None:
        self._cov_type = cov_type

    def get_type(self) -> str:
        return self._cov_type

    def is_type_set(self) -> bool:
        return self._cov_type != ""

    def is_file_lineno_hit(
        self,
        target_file: str,
        lineno: int,
        resolve_name: bool = False
    ) -> bool:
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

        logger.info("File type")
        target_key = target_file
        # Resolve name if required. This is needed to normalise filenames.
        if resolve_name:
            splits = target_file.split(".")
            potentials = []
            curr = ""
            for s2 in splits:
                curr += s2
                potentials.append(curr + ".py")
                curr += "/"
            logger.info(f"Potentials: {str(potentials)}")
            for potential_key in self.file_map:
                logger.info(f"Scanning {str(potential_key)}")
                for p in potentials:
                    if potential_key.endswith(p):
                        found_key = potential_key
                        break
            logger.info(f"Found key: {str(found_key)}")
            if found_key == "":
                logger.info("Could not find key")
                return False
            target_key = found_key

        # Return False if file is not in file_map
        if target_key not in self.file_map:
            logger.info("Target key is not in file_map")
            return False

        # Return True if lineno is in the relevant filemap value.
        if lineno in self.file_map[target_key]:
            logger.info("Success")
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
        fuzz_key = None
        if funcname in self.covmap:
            fuzz_key = funcname
        elif utils.demangle_cpp_func(funcname) in self.covmap:
            fuzz_key = utils.demangle_cpp_func(funcname)
        elif utils.normalise_str(funcname) in self.covmap:
            fuzz_key = utils.normalise_str(funcname)

        if fuzz_key is None or fuzz_key not in self.covmap:
            return []
        return self.covmap[fuzz_key]

    def get_hit_summary(
        self,
        funcname: str
    ) -> Tuple[Optional[int], Optional[int]]:
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

        if fuzz_key is None:
            return None, None

        lines_hit = [ht for ln, ht in self.covmap[fuzz_key] if ht > 0]
        return len(self.covmap[fuzz_key]), len(lines_hit)


def load_llvm_coverage(
    target_dir: str,
    target_name: Optional[str] = None
) -> CoverageProfile:
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
    coverage_reports = utils.get_all_files_in_tree_with_regex(target_dir, ".*\.covreport$")
    logger.info(f"Found {len(coverage_reports)} coverage reports")

    # Check if there is a meaningful profile and if not, we need to use all.
    found_name: Optional[str] = None
    if target_name is not None:
        for cov_report in coverage_reports:
            if target_name in cov_report:
                found_name = target_name

    cp = CoverageProfile()
    for profile_file in coverage_reports:
        # If only coverage from a specific report should be used then filter
        # here. Otherwise, include coverage from all reports.
        if found_name is not None and found_name not in profile_file:
            continue

        logger.info(f"Reading coverage report: {profile_file}")
        with open(profile_file, 'rb') as pf:
            curr_func = None
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
                        curr_func = line.split(":")[1].replace(" ", "").replace(":", "")
                    else:
                        curr_func = line.replace(" ", "").replace(":", "")
                    curr_func = utils.demangle_cpp_func(curr_func)
                    cp.covmap[curr_func] = list()
                # This parses Branch cov info in the form of:
                #  |  Branch (81:7): [True: 1.2k, False: 0]
                if curr_func and "Branch (" in line:
                    try:
                        line_number = int(line.split('(')[1].split(':')[0])
                    except Exception:
                        continue
                    try:
                        column_number = int(line.split(':')[1].split(')')[0])
                    except Exception:
                        continue

                    try:
                        true_hit = int(line.split('True:')[1].split(',')[0].replace(
                            "k", "00").replace(
                                "M", "0000").replace(
                                    ".", ""))
                    except Exception:
                        continue
                    try:
                        false_hit = int(line.split('False:')[1].replace("]", "").replace(
                            "k", "00").replace(
                                "M", "0000").replace(
                                    ".", ""))
                    except Exception:
                        continue
                    branch_string = f'{curr_func}:{line_number},{column_number}'
                    cp.branch_cov_map[branch_string] = (true_hit, false_hit)
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

                    # Extract hit count
                    # Write out numbers e.g. 1.2k into 1200 and 5.99M to 5990000
                    try:
                        hit_times = int(
                            line.split("|")[1].replace(
                                "k", "00").replace(
                                    "M", "0000").replace(
                                        ".", ""))
                    except Exception:
                        hit_times = 0
                    # Add source code line and hitcount to coverage map of current function
                    logger.debug(f"reading coverage: {curr_func} "
                                 f"-- {line_number} -- {hit_times}")
                    cp.covmap[curr_func].append((line_number, hit_times))
    return cp


def load_python_json_coverage(
    json_file: str,
    strip_pyinstaller_prefix: bool = True
):
    """Loads a python json coverage file.

    The specific json file that is handled by the coverage output from:
    - https://coverage.readthedocs.io/en/latest/cmd.html#json-reporting-coverage-json

    Return a CoverageProfile
    """
    import json
    cp = CoverageProfile()
    cp.set_type("file")

    coverage_reports = utils.get_all_files_in_tree_with_regex(json_file, ".*all_cov.json$")
    logger.info(f"FOUND JSON FILES: {str(coverage_reports)}")

    if len(coverage_reports) > 0:
        json_file = coverage_reports[0]

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

    return cp


if __name__ == "__main__":
    logging.basicConfig()
    logger.info("Starting coverage loader")
    cp = load_python_json_coverage("total_coverage.json")

    logger.info("Coverage map keys")
    for fn in cp.file_map:
        logger.info(fn)
    logger.info("Coverage loader end")
    is_hit = cp.is_file_lineno_hit("yaml.reader", 150, True)
    logger.info(f"Checking hit {is_hit}")
