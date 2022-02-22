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

import os
import sys
import yaml
import logging
import argparse

import fuzz_data_loader
import fuzz_html
import fuzz_utils

l = logging.getLogger(name=__name__)

def correlate_binaries_to_logs(binaries_dir):
    pairings = fuzz_utils.scan_executables_for_fuzz_introspector_logs(args.binaries_dir)
    print("Pairings: %s"%(str(pairings)))
    with open("exe_to_fuzz_introspector_logs.yaml", "w+") as etf:
        etf.write(yaml.dump({'pairings' : pairings}))


def run_analysis_on_dir(target_folder,
        git_repo_url,
        coverage_url,
        analyses_to_run,
        correlation_file):
    l.info("[+] Loading profiles")
    profiles = fuzz_data_loader.load_all_profiles(target_folder)
    if len(profiles) == 0:
        l.info("Found no profiles. Exiting")
        exit(0)

    correlation_dict = {}
    if correlation_file != "" and os.path.isfile(correlation_file):
        l.info("Loading correlation file %s"%(correlation_file))
        with open(correlation_file, "r") as yf:
            try:
                correlation_dict = yaml.safe_load(yf)
            except:
                print("Exception")

    l.info("[+] Accummulating profiles")
    for profile in profiles:
        profile.accummulate_profile(target_folder)
        print(correlation_dict)
        print("Profile file: %s"%(os.path.basename(profile.introspector_data_file)))
        if "pairings" in correlation_dict:
            for elem in correlation_dict['pairings']:
                if os.path.basename(profile.introspector_data_file) in "%s.data"%(elem['fuzzer_log_file']):
                    profile.binary_executable = "%s"%(elem['executable_path'])
                    print("Found a match")

    l.info("[+] Creating project profile")
    project_profile = fuzz_data_loader.MergedProjectProfile(profiles)

    l.info("[+] Refining profiles")
    for profile in profiles:
        profile.refine_paths(project_profile.basefolder)

    print("%s"%(str(analyses_to_run)))

    l.info("[+] Creating HTML report")
    fuzz_html.create_html_report(
            profiles,
            project_profile,
            analyses_to_run,
            coverage_url,
            git_repo_url,
            project_profile.basefolder)

def parse_cmdline():
    parser = argparse.ArgumentParser()

    subparsers = parser.add_subparsers(dest='command')

    # Report generation
    report_parser = subparsers.add_parser(
            'report', help='generate fuzz-introspector HTML report')
    report_parser.add_argument("--target_dir",
                        type=str,
                        help="Directory where the data files are",
                        required=True)
    report_parser.add_argument('--git_repo_url',
                        type=str,
                        help="Git repository with the source code",
                        default="")
    report_parser.add_argument('--coverage_url',
                        type=str,
                        help="URL with coverage information", 
                        default="/covreport/linux")
    report_parser.add_argument("--analyses",
                        nargs="+",
                        default=["OptimalTargets", "OptimalCoverageTargets"],
                        help="Analyses to run. Available options: OptimalTargets, FuzzEngineInput")
    report_parser.add_argument("--correlation_file",
                        type=str,
                        default="",
                        help="File with correlation data")

    # Correlate binary files to fuzzerLog files
    correlate_parser = subparsers.add_parser(
            'correlate', help='correlate executable files to fuzzer introspector logs')
    correlate_parser.add_argument("--binaries_dir",
                        type=str,
                        required=True,
                        help="Directory with binaries to scan for Fuzz introspector tags")

    args = parser.parse_args()
    return args

if __name__ == "__main__":
    l.info("Running fuzz introspector post-processing")
    logging.basicConfig(level=logging.INFO)
    args = parse_cmdline()
    if args.command == 'report':
        run_analysis_on_dir(args.target_dir, args.git_repo_url, args.coverage_url, args.analyses, args.correlation_file)
    elif args.command == 'correlate':
        correlate_binaries_to_logs(args.binaries_dir)
    l.info("Ending fuzz introspector post-processing")
