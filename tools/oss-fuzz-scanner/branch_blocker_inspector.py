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
"""Module for reporting details about branch blockers for a given project.

The "Function where blocker is" printed for each blocker is the function where
the blocker is located, meaning this is where the blocker branch is. In order
to overcome the blocker, you will need to create a fuzzer that passes the
specific condition.
"""

import sys
import json
import scanner


def print_blocker_details(project_name, max_blockers_per_fuzzer=5):
    # Get an iterator for all reports in the last 100 days
    report_generator = scanner.get_all_reports([project_name],
                                               days_to_analyse=100,
                                               interval_size=1)

    # Only use the first working report
    project, date_as_str, introspector_project = next(report_generator)

    # For each profile, print the top blockers.
    for profile in introspector_project.profiles:
        print("Profile: %s has %d blokers" %
              (profile.identifier, len(profile.branch_blockers)))
        if len(profile.branch_blockers) == 0:
            continue

        idx = 0
        for blocker_entry in profile.branch_blockers:
            if idx > max_blockers_per_fuzzer:
                break
            idx += 1
            blocker_code_location = "%s:%s" % (
                blocker_entry.source_file, blocker_entry.branch_line_number)
            block_info = {
                "Function where blocker is":
                blocker_entry.function_name,
                "Blocker source code location":
                blocker_code_location,
                "Complexity blocked":
                blocker_entry.blocked_not_covered_complexity,
                "Num of unique blocked funcs":
                len(blocker_entry.blocked_unique_funcs),
                "Unique blocked funcs:":
                str(blocker_entry.blocked_unique_funcs),
            }
            print(json.dumps(block_info, indent=2))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 branch_blocker_inspector.py project_name")
        sys.exit(0)
    project_name = sys.argv[1]
    print_blocker_details(project_name)
