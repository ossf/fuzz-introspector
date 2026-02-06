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
from typing import Dict, List, Optional, Any


def get_date_at_offset_as_str(day_offset: int = -1) -> str:
    datestr = (datetime.date.today() +
               datetime.timedelta(day_offset)).strftime("%Y-%m-%d")
    return datestr


class Project:
    __slots__ = ('name', 'language', 'date', 'coverage_data',
                 'introspector_data', 'fuzzer_count', 'project_repository',
                 'light_analysis', 'recent_results')

    def __init__(self, name: str, language: str, date: str,
                 coverage_data: Optional[Dict[str, Any]],
                 introspector_data: Optional[Dict[str,
                                                  Any]], fuzzer_count: int,
                 project_repository: Optional[str], light_analysis: Dict[Any,
                                                                         Any],
                 recent_results: Optional[Dict[str, Any]]):
        self.name = name
        self.language = language
        self.date = date
        self.coverage_data = coverage_data
        self.introspector_data = introspector_data
        self.fuzzer_count = fuzzer_count
        self.project_repository = project_repository
        self.light_analysis = light_analysis
        self.recent_results = recent_results

    def has_introspector(self) -> bool:
        return self.introspector_data is not None

    def has_recent_results(self) -> bool:
        return self.recent_results is not None and sum(
            len(ff) for ff in self.recent_results) > 0


class DBTimestamp:
    __slots__ = ('date', 'project_count', 'fuzzer_count', 'function_count',
                 'function_coverage_estimate', 'accummulated_lines_total',
                 'accummulated_lines_covered')

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
    __slots__ = ('all_projects', 'total_number_of_projects', 'total_fuzzers',
                 'total_functions', 'language_count')

    def __init__(self, all_projects: List[Project],
                 total_number_of_projects: int, total_fuzzers: int,
                 total_functions: int, language_count: Dict[str, int]):
        self.all_projects = all_projects
        self.total_number_of_projects = total_number_of_projects
        self.total_fuzzers = total_fuzzers
        self.total_functions = total_functions
        self.language_count = language_count


class ProjectTimestamp:
    __slots__ = ('project_name', 'date', 'language', 'coverage_data',
                 'introspector_data', 'fuzzer_count', 'introspector_url',
                 'project_url', 'project_repository')

    def __init__(self,
                 project_name: str,
                 date: str,
                 language: str,
                 coverage_data: Optional[Dict[str, Any]],
                 introspector_data: Optional[Dict[str, Any]],
                 fuzzer_count: int,
                 introspector_url: Optional[str] = None,
                 project_url: Optional[str] = None,
                 project_repository: Optional[str] = None):
        self.project_name = project_name
        # date in the format Y-m-d
        self.date = date
        self.language = language
        self.coverage_data = coverage_data
        self.introspector_data = introspector_data
        self.fuzzer_count = fuzzer_count
        self.introspector_url = introspector_url
        self.project_url = project_url
        self.project_repository = project_repository

    def has_introspector(self) -> bool:
        return self.introspector_data is not None


class Function:
    __slots__ = ('name', 'project', 'is_reached', 'runtime_code_coverage',
                 'function_filename', 'reached_by_fuzzers', 'cov_fuzzers',
                 'comb_fuzzers', 'code_coverage_url',
                 'accummulated_cyclomatic_complexity',
                 'llvm_instruction_count', 'undiscovered_complexity',
                 'function_arguments', 'function_debug_arguments',
                 'return_type', 'function_argument_names', 'raw_function_name',
                 'source_line_begin', 'source_line_end', 'callsites',
                 'calldepth', 'func_signature', 'debug_data', 'is_accessible',
                 'is_jvm_library', 'is_enum_class', 'is_static', 'need_close',
                 'exceptions', 'asserts')

    def __init__(self,
                 name: str,
                 project: str,
                 is_reached: bool = False,
                 runtime_code_coverage: float = 0.0,
                 function_filename: str = "",
                 reached_by_fuzzers: Optional[List[str]] = None,
                 cov_fuzzers: Optional[List[str]] = None,
                 comb_fuzzers: Optional[List[str]] = None,
                 code_coverage_url: str = "",
                 accummulated_cyclomatic_complexity: int = 0,
                 llvm_instruction_count: int = 0,
                 undiscovered_complexity: int = 0,
                 function_arguments: Optional[List[str]] = None,
                 function_debug_arguments: Optional[List[str]] = None,
                 return_type: str = "",
                 function_argument_names: Optional[List[str]] = None,
                 raw_function_name: str = "",
                 source_line_begin: int = -1,
                 source_line_end: int = -1,
                 callsites: Optional[Dict[str, List[str]]] = None,
                 calldepth: int = 0,
                 func_signature: str = '',
                 debug_data: Optional[Dict[str, Any]] = None,
                 is_accessible: bool = True,
                 is_jvm_library: bool = False,
                 is_enum_class: bool = False,
                 is_static: bool = False,
                 need_close: bool = False,
                 exceptions: Optional[List[str]] = None,
                 asserts: Optional[List[Dict[str, Any]]] = None):
        self.name = name
        self.function_filename = function_filename
        self.project = project
        self.is_reached = is_reached
        self.runtime_code_coverage = runtime_code_coverage
        self.reached_by_fuzzers = reached_by_fuzzers if reached_by_fuzzers is not None else []
        self.cov_fuzzers = cov_fuzzers if cov_fuzzers is not None else []
        self.comb_fuzzers = comb_fuzzers if comb_fuzzers is not None else []
        self.code_coverage_url = code_coverage_url
        self.accummulated_cyclomatic_complexity = accummulated_cyclomatic_complexity
        self.llvm_instruction_count = llvm_instruction_count
        self.undiscovered_complexity = undiscovered_complexity
        self.function_arguments = function_arguments if function_arguments is not None else []
        self.function_debug_arguments = function_debug_arguments if function_debug_arguments is not None else []
        self.function_argument_names = function_argument_names if function_argument_names is not None else []
        self.return_type = return_type
        self.raw_function_name = raw_function_name
        self.source_line_begin = source_line_begin
        self.source_line_end = source_line_end
        self.callsites = callsites if callsites is not None else {}
        self.calldepth = calldepth
        self.func_signature = func_signature
        self.debug_data = debug_data if debug_data is not None else {}
        self.is_accessible = is_accessible
        self.is_jvm_library = is_jvm_library
        self.is_enum_class = is_enum_class
        self.is_static = is_static
        self.need_close = need_close
        self.exceptions = exceptions if exceptions is not None else []
        self.asserts = asserts if asserts is not None else []

        # Handles the case when function signature is not available
        # Majorly used for python project
        if self.func_signature == 'N/A':
            self.func_signature = self.name

    def to_dict(self) -> Dict[str, Any]:
        return {
            'function_name': self.name,
            'function_arguments': self.function_arguments,
            'project': self.project,
            'runtime_code_coverage': self.runtime_code_coverage,
            'return_type': self.return_type,
            'function_argument_names': self.function_argument_names,
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
            'exceptions': self.exceptions,
            'assert_stmts': self.asserts,
            'reached-by-fuzzers': self.reached_by_fuzzers,
            'cov_fuzzers': self.cov_fuzzers,
            'comb_fuzzers': self.comb_fuzzers,
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
