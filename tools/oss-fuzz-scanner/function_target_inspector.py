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
"""Module for finding functions with no coverage but a lot of complexity.

These often consitute good targets for fuzzers, and, likely missing important
functions for an existing fuzzing set up."""
import sys
import json
import scanner


def print_function_details(project_name, functions_to_show=5):
    # Scan for Fuzz Introspector reports in the last 100 days
    report_generator = scanner.get_all_reports([project_name], 100, 1)

    # Get the first report and run fuzz introspector on it.
    project, date_as_str, introspector_project = next(report_generator)

    # Get dictionary of all functions
    all_functions = introspector_project.proj_profile.get_all_functions()

    # Create list of names of functions with 0% code coverage.
    not_hit = []
    for function_name in all_functions:
        cov_percentage = introspector_project.proj_profile.get_func_hit_percentage(
            function_name)
        if cov_percentage == 0.0:
            # We rank the functions by complexity at end so extract this
            # data here as well.
            function_profile = all_functions[function_name]
            not_hit.append(
                (function_name, function_profile.cyclomatic_complexity,
                 function_profile.new_unreached_complexity,
                 function_profile.total_cyclomatic_complexity))

    print("Stats as of %s-%s-%s" %
          (date_as_str[0:4], date_as_str[4:6], date_as_str[6:]))
    print("Functions with 0 coverage: %d" % (len(not_hit)))
    print("Most complex functions with no code coverage:")
    not_hit.sort(key=lambda e: e[1], reverse=True)
    for i in range(min(len(not_hit), functions_to_show)):
        func_name, complexity, unreached_complexity, acc_complexity = not_hit[
            i]
        interesting_func = {
            "function name": func_name,
            "code-coverage": 0.0,
            "cyclomatic complexity": complexity,
            "accummulated complexity": acc_complexity,
            "unreached complexity": unreached_complexity
        }
        print(json.dumps(interesting_func, indent=2))


if __name__ == "__main__":
    project_name = sys.argv[1]
    print_function_details(project_name)
