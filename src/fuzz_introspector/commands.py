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
from fuzz_introspector import data_loader
from fuzz_introspector import html_report
from fuzz_introspector import utils
from fuzz_introspector.datatypes import project_profile

logger = logging.getLogger(name=__name__)


def correlate_binaries_to_logs(binaries_dir: str) -> int:
    pairings = utils.scan_executables_for_fuzz_introspector_logs(binaries_dir)
    logger.info(f"Pairings: {str(pairings)}")
    with open("exe_to_fuzz_introspector_logs.yaml", "w+") as etf:
        etf.write(yaml.dump({'pairings': pairings}))
    return constants.APP_EXIT_SUCCESS


def run_analysis_on_dir(
    target_folder: str,
    coverage_url: str,
    analyses_to_run: List[str],
    correlation_file: str,
    enable_all_analyses: bool,
    report_name: str,
    language: str,
    parallelise: bool = True
) -> int:
    if enable_all_analyses:
        for analysis_interface in analysis.get_all_analyses():
            if analysis_interface.get_name() not in analyses_to_run:
                analyses_to_run.append(analysis_interface.get_name())

    logger.info("[+] Loading profiles")
    profiles = data_loader.load_all_profiles(target_folder, language, parallelise)
    if len(profiles) == 0:
        logger.info("Found no profiles. Exiting")
        return constants.APP_EXIT_ERROR

    input_bugs = data_loader.try_load_input_bugs()
    logger.info(f"[+] Loaded {len(input_bugs)} bugs")

    logger.info("[+] Correlating executables to Fuzz introspector reports")
    correlation_dict = utils.data_file_read_yaml(correlation_file)
    if correlation_dict is not None and "pairings" in correlation_dict:
        for profile in profiles:
            profile.correlate_executable_name(correlation_dict)
    else:
        logger.info("- Nothing to correlate")

    logger.info("[+] Accummulating profiles")
    for profile in profiles:
        profile.accummulate_profile(target_folder)

    logger.info("[+] Creating project profile")
    proj_profile = project_profile.MergedProjectProfile(profiles)

    logger.info(
        f"[+] All coverage files {proj_profile.get_profiles_coverage_files()}"
    )

    logger.info("[+] Refining profiles")
    for profile in profiles:
        profile.refine_paths(proj_profile.basefolder)

    # logger.info("[+] Loading branch profiles")
    # branch_profiles = data_loader.load_all_branch_profiles(target_folder)
    # if len(branch_profiles) == 0:
    #     logger.info("[X][X] Found no branch profiles!")

    # Overlay coverage in each profile
    for profile in profiles:
        analysis.overlay_calltree_with_coverage(
            profile,
            proj_profile,
            coverage_url,
            proj_profile.basefolder
        )

    logger.info(f"Analyses to run: {str(analyses_to_run)}")

    logger.info("[+] Creating HTML report")
    html_report.create_html_report(
        profiles,
        proj_profile,
        analyses_to_run,
        coverage_url,
        proj_profile.basefolder,
        report_name
    )
    return constants.APP_EXIT_SUCCESS
