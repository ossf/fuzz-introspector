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

import datetime


def get_date_at_offset_as_str(day_offset=-1):
    datestr = (datetime.date.today() +
               datetime.timedelta(day_offset)).strftime("%Y-%m-%d")
    return datestr


class DBTimestamp:

    def __init__(self, date, project_count, fuzzer_count, function_count):
        self.date = date
        self.project_count = project_count
        self.fuzzer_count = fuzzer_count
        self.function_count = function_count


class DBSummary:

    def __init__(self, all_projects, total_number_of_projects, total_fuzzers,
                 total_functions, language_count):
        self.all_projects = all_projects
        self.total_number_of_projects = total_number_of_projects
        self.total_fuzzers = total_fuzzers
        self.total_functions = total_functions
        self.language_count = language_count


class ProjectTimestamp:

    def __init__(self, project_name, date, coverage_lines, coverage_functions,
                 static_reachability, fuzzer_count):
        self.project_name = project_name
        # date in the format Y-m-d
        self.date = date
        self.coverage_lines = coverage_lines
        self.coverage_functions = coverage_functions
        self.static_reachability = static_reachability
        self.fuzzer_count = fuzzer_count


class Project:

    def __init__(self, name, language, fuzz_count, reach, runtime_cov,
                 introspector_report_url, code_coverage_report_url):
        self.name = name
        self.language = language
        self.fuzz_count = fuzz_count
        self.reach = reach
        self.runtime_cov = runtime_cov
        self.introspector_report_url = introspector_report_url
        self.code_coverage_report_url = code_coverage_report_url


class Function:

    def __init__(self,
                 name,
                 project,
                 is_reached=False,
                 runtime_code_coverage=0.0,
                 function_filename="",
                 reached_by_fuzzers=0,
                 code_coverage_url="",
                 accummulated_cyclomatic_complexity=0,
                 llvm_instruction_count=0,
                 undiscovered_complexity=0):
        self.name = name
        self.function_filename = function_filename
        self.project = project
        self.is_reached = is_reached
        self.runtime_code_coverage = runtime_code_coverage
        self.reached_by_fuzzers = reached_by_fuzzers
        self.coverage_by_fuzzers = 3
        self.code_coverage_url = code_coverage_url
        self.accummulated_cyclomatic_complexity = accummulated_cyclomatic_complexity
        self.llvm_instruction_count = llvm_instruction_count
        self.undiscovered_complexity = undiscovered_complexity


class BranchBlocker:

    def __init__(self, project_name, function_name, unique_blocked_coverage):
        self.project_name = project_name
        self.function_name = function_name
        self.unique_blocked_coverage = unique_blocked_coverage
