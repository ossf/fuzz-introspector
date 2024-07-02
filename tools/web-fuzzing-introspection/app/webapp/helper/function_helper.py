# Copyright 2024 Fuzz Introspector Authors
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

import sys
from typing import Dict, List, Any

from .. import models


def search_function_by_return_type(target_list: List[models.Function],
                                   needed_return_type: str,
                                   project_name: str) -> List[Dict[str, Any]]:
    """
        Find all the functions for the target project from the target list
        that returns the needed return type. The found function list is
        then convert to a list of dict for returning.
    """
    # Obtain the plain return type by removing generics
    needed_return_type = needed_return_type.split('<')[0]

    functions = _filter_unrelated_functions(target_list, project_name, True)

    functions = [
        function for function in functions
        if function.return_type == needed_return_type
    ]

    return convert_functions_to_list_of_dict(functions)


def filter_sort_functions(target_list: List[models.Function],
                          project_name: str,
                          is_filter: bool) -> List[Dict[str, Any]]:
    """
        Find all the functions for the target project with the provided
        project name. Then apply filtering and sorting to the resulting
        list. Lastly, convert the list of Function object to a list of
        Dict for json return.
    """

    functions = _filter_unrelated_functions(target_list, project_name,
                                            is_filter)

    return convert_functions_to_list_of_dict(
        _sort_functions_by_fuzz_worthiness(functions))


def _filter_unrelated_functions(target_list: List[models.Function],
                                project_name: str,
                                is_filter: bool) -> List[models.Function]:
    """
        Filter unrelated functions in a provided function list if
        it meet any of the following conditions.
        1) Fuzzing related methods / functions
        2) Functions with name contains word "exception / error / test"
    """
    excluded_function_name = [
        'fuzzertestoneinput', 'fuzzerinitialize', 'fuzzerteardown',
        'exception', 'error', 'test'
    ]

    if is_filter:
        functions = [
            target for target in target_list
            if (target.project == project_name and target.is_accessible
                and not target.is_jvm_library
                and len(target.function_arguments) > 0 and not any(
                    function_name in target.name.lower()
                    for function_name in excluded_function_name))
        ]
    else:
        functions = [
            target for target in target_list if target.project == project_name
        ]

    return functions


def _sort_functions_by_fuzz_worthiness(
        functions: List[models.Function]) -> List[models.Function]:
    """
        Sort the function list according to the following criteria in order.
        The order is acscending unless otherwise specified.
        For boolean sorting, False is always in front of True in acscending order.
        1) If the function is reached by any existing fuzzers.
        2) If the function belongs to a enum class (only for JVM project).
        3) The runtime code coverage of the function.
        4) The accumulated cyclomatic complexity of the function in descending order.
        5) The number of arguments of this function in descending order.
        6) The number of how many fuzzers reached this target function.
    """

    return sorted(
        functions,
        key=lambda item:
        (item.is_reached, item.is_enum_class, item.runtime_code_coverage, -item
         .accummulated_cyclomatic_complexity, -len(item.function_arguments),
         len(item.reached_by_fuzzers)),
        reverse=False)


def convert_functions_to_list_of_dict(
        functions: List[models.Function]) -> List[Dict[str, Any]]:
    """Convert a function list to a list of dict"""
    sorted_function_dict_list_by_fuzz_worthiness = []
    for function in functions:
        sorted_function_dict_list_by_fuzz_worthiness.append({
            'function_name':
            function.name,
            'function_filename':
            function.function_filename,
            'raw_function_name':
            function.raw_function_name,
            'is_reached':
            function.is_reached,
            'accummulated_complexity':
            function.accummulated_cyclomatic_complexity,
            'function_argument_names':
            function.function_argument_names,
            'function_arguments':
            function.function_arguments,
            'function_signature':
            function.func_signature,
            'reached_by_fuzzers':
            function.reached_by_fuzzers,
            'return_type':
            function.return_type,
            'runtime_coverage_percent':
            function.runtime_code_coverage,
            'source_line_begin':
            function.source_line_begin,
            'source_line_end':
            function.source_line_end,
            'debug_summary':
            function.debug_data,
            'is_enum_class':
            function.is_enum_class,
            'is_static':
            function.is_static,
            'exceptions':
            function.exceptions
        })
    return sorted_function_dict_list_by_fuzz_worthiness
