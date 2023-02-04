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
"""Diff introspector reports"""

import os
import json

from fuzz_introspector import (exceptions)


def diff_two_reports(report_first_path, report_second_path):
    """Diffs two fuzz introspector json reports.

    Takes two file paths as argument and will log the difference between the
    two. Each of the files are assumed to be a `summary.json` file generated
    by Fuzz Introspector during a report generation.

    Lightly, this functions will interpret it such that `report_first_path` was
    the first report generated and `report_second` the one most recently
    generated after some modifications aiming at improving the fuzzing set up.

    :param report_first_path: Path to the first introspector report.
    :type report_first_path: str

    :param report_second_path: Path to the second introspector report.
    :type report_second_[ath: str
    """

    if not os.path.isfile(report_first_path):
        raise exceptions.DataLoaderError('First report not present')

    if not os.path.isfile(report_second_path):
        raise exceptions.DataLoaderError('Second report not present')

    with open(report_first_path, "r") as report1_f:
        first_report = json.load(report1_f)
    with open(report_second_path, "r") as report2_f:
        second_report = json.load(report2_f)

    _compare_report_dictionaries(first_report, second_report)


def _compare_numericals(num1, num2, title="", to_print=True) -> int:
    """Compares two numbers and prints a message conveniently

    Returns:
      -1 if num1 < num2
      0 if num1 == num2
      1 if num1 > num2
    """
    if num1 < num2:
        msg = "Report 2 has a larger %s than report 1" % (title)
        ret_val = -1
    if num1 == num2:
        msg = "Report 2 has similar %s to report 1" % (title)
        ret_val = 0
    if num1 > num2:
        msg = "Report 2 has less %s than report 1" % (title)
        ret_val = 1
    if to_print:
        print("%s - {report 1: %s / report 2: %s})" %
              (msg, str(num1), str(num2)))

    return ret_val


def _compare_summary_of_all_functions(first_report, second_report):
    all_funcs1 = first_report['MergedProjectProfile']['all-functions']
    all_funcs2 = second_report['MergedProjectProfile']['all-functions']

    report2_smaller_cov = []
    report2_larger_cov = []

    report1_reached_only = []
    report2_reached_only = []
    for func1 in all_funcs1:
        # Find the relevant func in func2
        func2 = None
        for tmp_func2 in all_funcs2:
            if func1['Func name'] == tmp_func2['Func name']:
                func2 = tmp_func2

        func1_cov = float(func1['Func lines hit %'].replace("%", ""))
        func2_cov = float(func2['Func lines hit %'].replace("%", ""))

        cmp = _compare_numericals(func1_cov, func2_cov, to_print=False)
        if cmp == -1:
            msg = "Report 2 has more coverage {%6s vs %6s} for %s" % (
                func1_cov,
                func2_cov,
                func2['Func name'],
            )
            report2_larger_cov.append(msg)
        if cmp == 1:
            msg = "Report 2 has less coverage {%6s vs %6s} for %s" % (
                func1_cov,
                func2_cov,
                func2['Func name'],
            )
            report2_smaller_cov.append(msg)

        func1_reachability = func1['Reached by Fuzzers']
        func2_reachability = func2['Reached by Fuzzers']

        if len(func1_reachability) != 0 and len(func2_reachability) == 0:
            report1_reached_only.append(func1['Func name'])
        if len(func1_reachability) == 0 and len(func2_reachability) != 0:
            report2_reached_only.append(func1['Func name'])

    print("\n## Code coverge comparison")
    print("The following functions report 2 has decreased code coverage:")
    for msg in report2_smaller_cov:
        print(msg)

    print("")
    print("The following functions report 2 has increased code coverage:")
    for msg in report2_larger_cov:
        print(msg)

    print("\n## Reachability comparison")

    if len(report1_reached_only) == 0 and len(report2_reached_only) == 0:
        print("The reachability in the reports is similar")
    else:
        print("The following functions are only reachable in report 1:")
        if len(report1_reached_only) > 0:
            for func_name in report1_reached_only:
                print(func_name)
        else:
            print(
                "- All functions reachable in report 1 are reachable in report 2"
            )

        print("")
        print("The following functions are only reachable in report 2:")
        if len(report2_reached_only) > 0:
            for func_name in report2_reached_only:
                print(func_name)
        else:
            print(
                "- All functions reachable in report 2 are reachable in report 1"
            )


def _compare_report_dictionaries(first_report, second_report):
    first_merged_profile = first_report['MergedProjectProfile']
    second_merged_profile = second_report['MergedProjectProfile']

    _compare_numericals(first_merged_profile['stats']['total-complexity'],
                        second_merged_profile['stats']['total-complexity'],
                        'Total complexity')

    # Summary of difference between all functions
    _compare_summary_of_all_functions(first_report, second_report)
