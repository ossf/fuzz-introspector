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

    def __init__(self, date, project_count, fuzzer_count, function_count,
                 function_coverage_estimate, accummulated_lines_total,
                 accummulated_lines_covered):
        self.date = date
        self.project_count = project_count
        self.fuzzer_count = fuzzer_count
        self.function_count = function_count
        self.function_coverage_estimate = function_coverage_estimate
        self.accummulated_lines_total = accummulated_lines_total
        self.accummulated_lines_covered = accummulated_lines_covered


class DBSummary:

    def __init__(self, all_projects, total_number_of_projects, total_fuzzers,
                 total_functions, language_count):
        self.all_projects = all_projects
        self.total_number_of_projects = total_number_of_projects
        self.total_fuzzers = total_fuzzers
        self.total_functions = total_functions
        self.language_count = language_count


class ProjectTimestamp:

    def __init__(self, project_name, date, language, coverage_data,
                 introspector_data, fuzzer_count):
        self.project_name = project_name
        # date in the format Y-m-d
        self.date = date
        self.language = language
        self.coverage_data = coverage_data
        self.introspector_data = introspector_data
        self.fuzzer_count = fuzzer_count

    def has_introspector(self) -> bool:
        return self.introspector_data != None


class Project:

    def __init__(self, name, language, date, coverage_data, introspector_data,
                 fuzzer_count):
        self.name = name
        self.language = language
        self.date = date
        self.coverage_data = coverage_data
        self.introspector_data = introspector_data
        self.fuzzer_count = fuzzer_count

    def has_introspector(self) -> bool:
        return self.introspector_data != None


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
                 undiscovered_complexity=0,
                 function_arguments=[],
                 return_type="",
                 function_argument_names=[],
                 raw_function_name=""):
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
        self.function_arguments = function_arguments
        self.function_argument_names = function_argument_names
        self.return_type = return_type
        self.raw_function_name = raw_function_name


class BranchBlocker:

    def __init__(self, project_name, function_name, unique_blocked_coverage):
        self.project_name = project_name
        self.function_name = function_name
        self.unique_blocked_coverage = unique_blocked_coverage


class BuildStatus:

    def __init__(self, project_name, fuzz_build_status, coverage_build_status,
                 introspector_build_status, language, introspector_build_log,
                 coverage_build_log, fuzz_build_log):
        self.project_name = project_name
        self.fuzz_build_status = fuzz_build_status
        self.coverage_build_status = coverage_build_status
        self.introspector_build_status = introspector_build_status
        self.language = language

        self.introspector_build_log = introspector_build_log
        self.coverage_build_log = coverage_build_log
        self.fuzz_build_log = fuzz_build_log
