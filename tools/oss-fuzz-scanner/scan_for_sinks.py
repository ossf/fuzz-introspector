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
"""Module for reporting details about a function in a project."""

import json

import scanner


def print_function_details(project_name):
    summary_generator = scanner.get_all_summaries([project_name], 2)

    try:
        project, date_as_str, summary_json = next(summary_generator)
    except:
        return
    #print(summary_json)
    summary_dict = json.loads(summary_json)
    for elem in summary_dict['analyses']['SinkCoverageAnalyser']:
        print("%30s :: %s : %s" %
              (project, elem['func_name'], str(elem['parent_func'])))


if __name__ == "__main__":
    """Instructions:
    The first argument needs to be a list of projects, separated by newline,
    that should be scanned for sinks. The output is a list of all the sinks
    found in the various projects."""
    with open('sinks.txt', 'r') as f:
        for proj in f:
            print_function_details(proj.replace("\n", ""))
