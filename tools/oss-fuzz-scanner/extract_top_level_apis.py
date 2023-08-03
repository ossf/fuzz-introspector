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
"""Helper for rapidly extracting top-level fuzzer functions."""

import os
import json
import requests


##### Helper logic for downloading fuzz inVDtrospector reports
# Download introspector report
def get_introspector_report_url_base(project_name, datestr):
    base_url = 'https://storage.googleapis.com/oss-fuzz-introspector/{0}/inspector-report/{1}/'
    project_url = base_url.format(project_name, datestr)
    return project_url


def get_introspector_report_url_summary(project_name, datestr):
    return get_introspector_report_url_base(project_name,
                                            datestr) + "summary.json"


def extract_introspector_report(project_name, date_str):
    introspector_summary_url = get_introspector_report_url_summary(
        project_name, date_str.replace("-", ""))

    # Read the introspector atifact
    try:
        raw_introspector_json_request = requests.get(introspector_summary_url,
                                                     timeout=10)
    except:
        return None
    try:
        introspector_report = json.loads(raw_introspector_json_request.text)
    except:
        return None
    return introspector_report


# Main function for extracting the relevant logic
def get_mapping_for_project(project_name):
    introspector_json_report = extract_introspector_report(
        project_name, '20230803')
    if introspector_json_report is None:
        return

    annotated_cfg = introspector_json_report['analyses']['AnnotatedCFG']
    mappings = dict()
    for fuzzer in annotated_cfg:
        targets = []
        for target_func in annotated_cfg[fuzzer]['destinations']:
            # Remove functions where there are no source file, e.g. libc functions
            if target_func['source-file'] == '':
                continue

            # Let's only get functions with complexity
            if target_func['cyclomatic-complexity'] < 5:
                continue
            targets.append(target_func)
            #print("- %s"%(target_func['function-name']))
        mappings[fuzzer] = {
            'top-level-fuzzer-target-functions': targets,
            'fuzzer_src_file': annotated_cfg[fuzzer]['src_file']
        }
    return mappings


projects_to_analyse = ['tinyxml2', 'htslib', 'sadfasdfsadf']
all_mps = dict()
for project in projects_to_analyse:
    mps = get_mapping_for_project(project)
    if mps is not None:
        all_mps[project] = mps
print(json.dumps(all_mps, indent=4))
