# Copyright 2022 Fuzz Introspector Authors
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
"""Module for creating JSON reports"""
import os
import json
import logging

from typing import (
    Any,
    Dict
)

from fuzz_introspector import constants


logger = logging.getLogger(name=__name__)


def _get_summary_dict() -> Dict[Any, Any]:
    """Returns the current json report on disk as a dictionary."""
    if not os.path.isfile(constants.SUMMARY_FILE):
        existing_contents = dict()
    else:
        with open(constants.SUMMARY_FILE, "r") as report_fd:
            existing_contents = json.load(report_fd)

    return existing_contents


def _overwrite_report_with_dict(new_dict: Dict[Any, Any]) -> None:
    """Writes `new_dict` as contents to the report on disk. Will overwrite any
    contents of the existing report.
    """
    # Write back the json file
    with open(constants.SUMMARY_FILE, 'w') as report_fd:
        json.dump(dict(new_dict), report_fd)


def add_analysis_dict_to_json_report(
    analysis_name: str,
    dict_to_add: Dict[Any, Any]
) -> None:
    """Wraps dictionary into an appropriate format

    Will overwrite the existing key/value pair for the analysis if it already
    exists as an analysis in the report.
    """
    contents = _get_summary_dict()
    if 'analyses' not in contents:
        contents['analyses'] = dict()
    contents['analyses'][analysis_name] = dict_to_add

    _overwrite_report_with_dict(contents)


def add_analysis_json_str_as_dict_to_report(
    analysis_name: str,
    json_str: str
) -> None:
    """Converts a json string to a dictionary and add it to the report.

    Will overwrite the existing key/value pair for the analysis if it already
    exists as an analysis in the report."""
    add_analysis_dict_to_json_report(analysis_name, json.loads(json_str))


def add_fuzzer_key_value_to_report(
    fuzzer_name: str,
    key: str,
    value: Any
) -> None:
    """Add the key/value pair to the json report under the fuzzer key.

    Will overwrite the existing key/value pair under the fuzzer if it already
    exists in the report.
    """
    contents = _get_summary_dict()

    if fuzzer_name not in contents:
        contents[fuzzer_name] = dict()
    contents[fuzzer_name][key] = value

    _overwrite_report_with_dict(contents)
