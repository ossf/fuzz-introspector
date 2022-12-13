# Copyright 2021 Fuzz Introspector Authors
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

"""Module for creating JSON reports for sink coverage"""
import os
import logging

from typing import List

from fuzz_introspector import analysis
from fuzz_introspector.datatypes import project_profile, fuzzer_profile


logger = logging.getLogger(name=__name__)


def create_json_report(
    profiles: List[fuzzer_profile.FuzzerProfile],
    proj_profile: project_profile.MergedProjectProfile,
    coverage_url: str
) -> None:
    """
    Generate specific json report for saving the injection sinks
    coverage for the fuzzing project. This method will output a json file
    which store all those reachable and coverage information for
    existing sink methods / functions in the fuzzing project.
    """

    logger.info(" - Creating JSON report for sink coverage")
    if not proj_profile.has_coverage_data():
        logger.error(
            "No files with coverage data was found. This is either "
            "because an error occurred when compiling and running "
            "coverage runs, or because the introspector run was "
            "intentionally done without coverage collection. In order "
            "to get optimal results coverage data is needed."
        )

    logger.info(" - Handling sink coverage analyses")
    analysis_array = analysis.get_all_analyses()
    for analysis_interface in analysis_array:
        if analysis_interface.get_name() == "SinkCoverageAnalysis":
            analysis_instance = analysis.instantiate_analysis_interface(
                analysis_interface
            )
            result_str = analysis_instance.analysis_func(
                None,
                None,
                proj_profile,
                profiles,
                None,
                coverage_url,
                None,
                True
            )

    report_name = "sink_coverage.json"
    if os.path.isfile(report_name):
        os.remove(report_name)

    # Write the json string to file
    with open(report_name, "a+") as file:
        file.write(result_str)
