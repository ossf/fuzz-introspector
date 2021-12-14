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
import argparse

import fuzz_data_loader
import fuzz_html
import fuzz_utils


def run_analysis_on_dir(target_folder,
        git_repo_url,
        coverage_url):
    # Load all the data needed
    print("[+] Loading profiles")
    profiles = fuzz_data_loader.load_all_profiles(target_folder)
    print("[+] Accummulating profiles")
    for profile in profiles:
        profile.accummulate_profile(target_folder)

    # Merge all profiles into a project profile    
    print("[+] Creating project profile")
    project_profile = fuzz_data_loader.MergedProjectProfile(profiles)

    # Find a base folder
    basefolder = project_profile.get_basefolder()
    #print("Base folder: %s"%(basefolder))

    print("[+] Refining profiles")
    for profile in profiles:
        fuzz_data_loader.refine_profile(profile)

    # Create the HTML report that can be viewed.
    if coverage_url == "":
        coverage_url = "http://localhost:8008/covreport/linux"

    print("[+] Creating HTML report")
    fuzz_html.create_html_report(profiles, project_profile, coverage_url, git_repo_url, basefolder)


def create_parser():
    parser = argparse.ArgumentParser()

    parser.add_argument("--target_dir", 
                        type=str,
                        help="Directory where the data files are",
                        required=True)
    
    parser.add_argument('--git_repo_url', 
                        type=str,
                        help="Git repository with the source code",
                        default="")
        
    parser.add_argument('--coverage_url', 
                        type=str,
                        help="URL with coverage information", 
                        default="")

    args = parser.parse_args()
    return args

if __name__ == "__main__":
    args = create_parser()

    print("Running fuzz introspector post-processing")
    run_analysis_on_dir(args.target_dir, args.git_repo_url, args.coverage_url)
    print("Ending fuzz introspector post-processing")
