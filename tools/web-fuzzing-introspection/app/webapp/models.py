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

import json
import datetime
from typing import Dict, List, Optional, Any


def get_date_at_offset_as_str(day_offset: int = -1) -> str:
    datestr = (datetime.date.today() +
               datetime.timedelta(day_offset)).strftime("%Y-%m-%d")
    return datestr


class Project:

    def __init__(self, name: str, language: str, date: str,
                 coverage_data: Optional[Dict[str, Any]],
                 introspector_data: Optional[Dict[str, Any]],
                 fuzzer_count: int, project_repository: Optional[str]):
        self.name = name
        self.language = language
        self.date = date
        self.coverage_data = coverage_data
        self.introspector_data = introspector_data
        self.fuzzer_count = fuzzer_count
        self.project_repository = project_repository

    def has_introspector(self) -> bool:
        return self.introspector_data != None


class DBTimestamp:

    def __init__(self, date: str, project_count: int, fuzzer_count: int,
                 function_count: int, function_coverage_estimate: float,
                 accummulated_lines_total: int,
                 accummulated_lines_covered: int):
        self.date = date
        self.project_count = project_count
        self.fuzzer_count = fuzzer_count
        self.function_count = function_count
        self.function_coverage_estimate = function_coverage_estimate
        self.accummulated_lines_total = accummulated_lines_total
        self.accummulated_lines_covered = accummulated_lines_covered


class DBSummary:

    def __init__(self, all_projects: List[Project],
                 total_number_of_projects: int, total_fuzzers: int,
                 total_functions: int, language_count: Dict[str, int]):
        self.all_projects = all_projects
        self.total_number_of_projects = total_number_of_projects
        self.total_fuzzers = total_fuzzers
        self.total_functions = total_functions
        self.language_count = language_count


class ProjectTimestamp:

    def __init__(self,
                 project_name: str,
                 date: str,
                 language: str,
                 coverage_data: Optional[Dict[str, Any]],
                 introspector_data: Optional[Dict[str, Any]],
                 fuzzer_count: int,
                 introspector_url: Optional[str] = None,
                 project_url: Optional[str] = None):
        self.project_name = project_name
        # date in the format Y-m-d
        self.date = date
        self.language = language
        self.coverage_data = coverage_data
        self.introspector_data = introspector_data
        self.fuzzer_count = fuzzer_count
        self.introspector_url = introspector_url
        self.project_url = project_url

    def has_introspector(self) -> bool:
        return self.introspector_data != None


class Function:

    def __init__(self,
                 name: str,
                 project: str,
                 is_reached: bool = False,
                 runtime_code_coverage: float = 0.0,
                 function_filename: str = "",
                 reached_by_fuzzers: List[str] = [],
                 code_coverage_url: str = "",
                 accummulated_cyclomatic_complexity: int = 0,
                 llvm_instruction_count: int = 0,
                 undiscovered_complexity: int = 0,
                 function_arguments: List[str] = [],
                 function_debug_arguments: List[str] = [],
                 return_type: str = "",
                 function_argument_names: List[str] = [],
                 raw_function_name: str = "",
                 date_str: str = "",
                 source_line_begin: int = -1,
                 source_line_end: int = -1,
                 callsites: Dict[str, List[str]] = {},
                 calldepth: int = 0,
                 func_signature: str = '',
                 debug_data: Dict[str, Any] = {},
                 is_accessible: bool = True,
                 is_jvm_library: bool = False,
                 is_enum_class: bool = False,
                 is_static: bool = False,
                 need_close: bool = False,
                 exceptions: List[str] = []):
        self.name = name
        self.function_filename = function_filename
        self.project = project
        self.is_reached = is_reached
        self.runtime_code_coverage = runtime_code_coverage
        self.reached_by_fuzzers = reached_by_fuzzers
        self.code_coverage_url = code_coverage_url
        self.accummulated_cyclomatic_complexity = accummulated_cyclomatic_complexity
        self.llvm_instruction_count = llvm_instruction_count
        self.undiscovered_complexity = undiscovered_complexity
        self.function_arguments = function_arguments
        self.function_debug_arguments = function_debug_arguments
        self.function_argument_names = function_argument_names
        self.return_type = return_type
        self.raw_function_name = raw_function_name
        self.date_str = date_str
        self.source_line_begin = source_line_begin
        self.source_line_end = source_line_end
        self.callsites = callsites
        self.calldepth = calldepth
        self.func_signature = func_signature
        self.debug_data = debug_data
        self.is_accessible = is_accessible
        self.is_jvm_library = is_jvm_library
        self.is_enum_class = is_enum_class
        self.is_static = is_static
        self.need_close = need_close
        self.exceptions = exceptions

    def to_dict(self) -> Dict[str, Any]:
        return {
            'function_name': self.name,
            'function_arguments': self.function_arguments,
            'project': self.project,
            'runtime_code_coverage': self.runtime_code_coverage,
            'return_type': self.return_type,
            'function_argument_names': self.function_argument_names,
            'function_arguments': self.function_arguments,
            'raw_function_name': self.raw_function_name,
            'accummulated_cyclomatic_complexity':
            self.accummulated_cyclomatic_complexity,
            'undiscovered_complexity': self.undiscovered_complexity,
            'calldepth': self.calldepth,
            'function_filename': self.function_filename,
            'is_accessible': self.is_accessible,
            'is_jvm_library': self.is_jvm_library,
            'is_enum_class': self.is_enum_class,
            'is_static': self.is_static,
            'exceptions': self.exceptions
        }


class BranchBlocker:

    def __init__(self, project_name: str, function_name: str,
                 unique_blocked_coverage: int, source_file: str,
                 blocked_unique_functions: List[str], src_linenumber: str):
        self.project_name = project_name
        self.function_name = function_name
        self.unique_blocked_coverage = unique_blocked_coverage
        self.blocked_unique_functions = blocked_unique_functions
        self.source_file = source_file
        self.src_linenumber = src_linenumber


class BuildStatus:

    def __init__(self, project_name: str, fuzz_build_status: bool,
                 coverage_build_status: bool, introspector_build_status: bool,
                 language: str, introspector_build_log: str,
                 coverage_build_log: str, fuzz_build_log: str):
        self.project_name = project_name
        self.fuzz_build_status = fuzz_build_status
        self.coverage_build_status = coverage_build_status
        self.introspector_build_status = introspector_build_status
        self.language = language

        self.introspector_build_log = introspector_build_log
        self.coverage_build_log = coverage_build_log
        self.fuzz_build_log = fuzz_build_log


class DebugStatus:

    def __init__(self, project_name: str, all_files_in_project: List[str],
                 all_functions_in_project: List[str],
                 all_global_variables: List[str], all_types: List[Dict[str,
                                                                       Any]]):
        self.project_name = project_name
        self.all_files_in_project = all_files_in_project
        self.all_functions_in_project = all_functions_in_project
        self.all_global_variables = all_global_variables
        self.all_types = all_types
