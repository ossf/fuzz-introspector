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


def add_dict_to_json_report(dict_to_add: Dict[Any, Any]) -> None:
    """Adds the contents of a dictionary to the contents the json report.
    This is an expensive operation in that it will load the json report
    to merge the contents.
    """
    logger.info("Adding contents to summary")
    if not os.path.isfile(constants.SUMMARY_FILE):
        existing_contents = dict()
    else:
        with open(constants.SUMMARY_FILE, "r") as report_fd:
            existing_contents = json.load(report_fd)

    # Update the contents
    existing_contents.update(dict_to_add)

    # Write back the json file
    with open(constants.SUMMARY_FILE, 'w') as report_fd:
        json.dump(existing_contents, report_fd)


def add_analysis_dict_to_json_report(
    analysis_name: str,
    dict_to_add: Dict[Any, Any]
) -> None:
    """Wraps dictionary into an appropriate format"""
    add_dict_to_json_report({'analyses': {analysis_name: dict_to_add}})


def add_analysis_json_str_as_dict_to_report(analysis_name: str, json_str: str) -> None:
    add_analysis_dict_to_json_report(analysis_name, json.loads(json_str))
