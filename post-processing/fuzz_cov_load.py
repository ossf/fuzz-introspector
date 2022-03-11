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
"""
Module for loading coverage files and parsing them into something we can use in Python.

At the moment only C/C++ is supported. Other languages coming up soon.
"""

import fuzz_utils
import logging

l = logging.getLogger(name=__name__)


class CoverageProfile:
    """
    Class for storing information about a runtime coverage report
    """
    def __init__(self):
        self.functions_hit = set()
        self.covmap = dict()
        self.covreports = list()

    def get_all_hit_functions(self):
        return self.covmap.keys()

    def get_hit_summary(self, funcname):
        """
        returns the hit summary of a give function, in the form of
        a tuple (total_function_lines, hit_lines)
        """
        if funcname not in self.covmap:
            return None, None
        lines_hit = [ht for ln, ht in self.covmap[funcname] if ht > 0]
        return len(self.covmap[funcname]), len(lines_hit)


def llvm_cov_load(target_dir, target_name=None):
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
    coverage_reports = fuzz_utils.get_all_files_in_tree_with_regex(target_dir, ".*\.covreport$")
    l.info("Found %d coverage reports" % len(coverage_reports))

    # Check if there is a meaningful profile and if not, we need to use all.
    found_name = False
    if target_name is not None:
        for pf in coverage_reports:
            if target_name in pf:
                found_name = True

    cp = CoverageProfile()
    for profile_file in coverage_reports:
        # If only coverage from a specific report should be used then filter
        # here. Otherwise, include coverage from all reports.
        if found_name and target_name not in profile_file:
            continue

        l.info("Reading coverage report: %s" % profile_file)
        with open(profile_file, 'rb') as pf:
            cp.covreports.append(profile_file)
            curr_func = None
            for line in pf:
                line = fuzz_utils.safe_decode(line)
                if line is None:
                    continue

                line = line.replace("\n", "")

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
                    cp.covmap[curr_func] = list()

                    # Normalise the function name and add it to functions_hit.
                    # Notice there is something quite odd here in that we keep function names
                    # both in cp.covmap and also cp.fuctions_hit. TODO: David, why was this
                    # set up using both? It would be smarter to just use cp.covmap?
                    fname = line
                    if ".cpp" in fname:
                        fname = fname.split(".cpp")[-1].replace(":", "")
                        fname = fuzz_utils.demangle_cpp_func(fname)
                    elif ".c" in fname:
                        fname = fname.split(".c")[-1].replace(":", "")
                    fname = fname.replace(":", "")
                    cp.functions_hit.add(fname)

                # Parse lines that signal specific line of code. These lines only
                # offer after the function names parsed above.
                # Example line:
                #  "   83|  5.99M|    char *kldfj = (char*)malloc(123);\n"
                if curr_func is not None and "|" in line:
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
                    cp.covmap[curr_func].append((line_number, hit_times))
    return cp


if __name__ == "__main__":
    print("Starting coverage loader")
    cp = llvm_cov_load(".")
    print("Functions hit:")
    for fn in cp.functions_hit:
        print(fn)

    print("Coverage map keys")
    for fn in cp.covmap:
        print(fn)
    print("Coverage loader end")
