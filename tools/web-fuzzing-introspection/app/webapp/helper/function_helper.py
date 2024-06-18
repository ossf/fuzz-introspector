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


def process_functions(target_list: List[models.Function], project_name: str,
                      is_filter: bool) -> List[models.Function]:
    """
        Found all the functions for the target project with the provided
        project name. Then apply filtering and sorting to the resulting
        list. Lastly, convert the list of Function object to a list of
        Dict for json return.
    """

    if is_filter:
        functions = [
            target for target in target_list
            if (target.project == project_name and target.is_accessible
                and not target.is_jvm_library
                and len(target.function_arguments) > 0)
        ]
    else:
        functions = [
            target for target in target_list if target.project == project_name
        ]

    return _convert_functions(_sort_functions(functions))


def _sort_functions(functions: List[models.Function]) -> List[models.Function]:
    """Sort the function list according to certain criteria."""

    return sorted(
        functions,
        key=lambda item:
        (item.is_reached, item.is_enum_class, item.runtime_code_coverage, -item
         .accummulated_cyclomatic_complexity, -len(item.function_arguments),
         len(item.reached_by_fuzzers)),
        reverse=False)


def _convert_functions(
        functions: List[models.Function]) -> List[Dict[str, Any]]:
    """Convert a function list to something we can return"""
    list_to_return = []
    for function in functions:
        list_to_return.append({
            'function_name': function.name,
            'function_filename': function.function_filename,
            'raw_function_name': function.raw_function_name,
            'is_reached': function.is_reached,
            'accummulated_complexity':
            function.accummulated_cyclomatic_complexity,
            'function_argument_names': function.function_argument_names,
            'function_arguments': function.function_arguments,
            'reached_by_fuzzers': function.reached_by_fuzzers,
            'return_type': function.return_type,
            'runtime_coverage_percent': function.runtime_code_coverage,
            'is_enum_class': function.is_enum_class
        })
    return list_to_return
