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
"""High-level routines and CLI entrypoints"""

import logging
import yaml
from typing import List

from fuzz_introspector import analysis
from fuzz_introspector import constants
from fuzz_introspector import diff_report
from fuzz_introspector import html_report
from fuzz_introspector import utils

logger = logging.getLogger(name=__name__)


def diff_two_reports(report1: str, report2: str) -> int:
    diff_report.diff_two_reports(report1, report2)
    return constants.APP_EXIT_SUCCESS


def correlate_binaries_to_logs(binaries_dir: str) -> int:
    pairings = utils.scan_executables_for_fuzz_introspector_logs(binaries_dir)
    logger.info(f"Pairings: {str(pairings)}")
    with open("exe_to_fuzz_introspector_logs.yaml", "w+") as etf:
        etf.write(yaml.dump({'pairings': pairings}))
    return constants.APP_EXIT_SUCCESS


def run_analysis_on_dir(target_folder: str,
                        coverage_url: str,
                        analyses_to_run: List[str],
                        correlation_file: str,
                        enable_all_analyses: bool,
                        report_name: str,
                        language: str,
                        output_json: List[str] = [],
                        parallelise: bool = True,
                        dump_files: bool = True) -> int:
    constants.should_dump_files = dump_files

    if enable_all_analyses:
        for analysis_interface in analysis.get_all_analyses():
            if analysis_interface.get_name() not in analyses_to_run:
                analyses_to_run.append(analysis_interface.get_name())

    introspection_proj = analysis.IntrospectionProject(language, target_folder,
                                                       coverage_url)
    introspection_proj.load_data_files(parallelise, correlation_file)

    logger.info(f"Analyses to run: {str(analyses_to_run)}")
    logger.info("[+] Creating HTML report")
    html_report.create_html_report(introspection_proj, analyses_to_run,
                                   output_json, report_name, dump_files)

    return constants.APP_EXIT_SUCCESS
