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
"""Test commands.py / generation of html report with correct url"""

import re
import os
import sys
import configparser

sys.path.append(os.path.dirname(os.path.realpath(__file__)) + "/../")

from fuzz_introspector import commands  # noqa: E402


def is_valid_gcloud_link(link):
    # Skip same page linkage
    if link.startswith('#') or link.startswith('?'):
        return True

    # Skip out of scope linkage
    if link.startswith('http'):
        if not link.startswith('https://storage.googleapis.com/'):
            return True

#    if link.startswith('https://storage.googleapis.com/'):
    file_name = link.split('/')[-1].split('#')[0].split('?')[0]
    if len(file_name.split('.')) == 1:
        return False
    else:
        return True


def extract_link_from_html(html):
    links = re.findall('href="([^\"]*)"', html)
    return links


def test_regression_427():
    """ Regression testing for Issue #427 """

    assert not is_valid_gcloud_link(
        "https://storage.googleapis.com/oss-fuzz-coverage/bluez/reports/20220807/linux"
    )
    assert is_valid_gcloud_link(
        "https://storage.googleapis.com/oss-fuzz-coverage/bluez/reports/20220807/linux/report.html"
    )


def test_run_analysis_on_dir():
    """Test links in HTML report generated for each YAML file"""

    # Retrieve test case list and config
    report_dir = "data/TestReport"
    config_file = "%s/config.properties" % report_dir

    if not os.path.isdir(report_dir):
        return
    if not os.path.isfile(config_file):
        return

    config = configparser.ConfigParser()
    config.read(config_file)

    # Loop through each project config
    for test_case in config:
        # Retrieve test case config
        if not os.path.isdir("./tmpdir"):
            os.mkdir("./tmpdir")
        os.chdir("./tmpdir")

        base_dir = "../%s/%s" % (report_dir, config.get(test_case, 'base_dir'))
        language = config.get(test_case, 'language')

        if not os.path.isdir(base_dir):
            continue

        # Execute command to generate report
        commands.run_analysis_on_dir(
            base_dir,
            "/covreport/linux",
            [
                "OptimalTargets",
                "RuntimeCoverageAnalysis",
                "FuzzEngineInputAnalysis",
                "FilePathAnalyser"
            ],
            "",
            False,
            "Dummy Name",
            language
        )

        # Temporary handling on fuzz_report.html only
        html_file = open("fuzz_report.html", "r")
        html = html_file.read()
        html_file.close()

        for link in extract_link_from_html(html):
            assert is_valid_gcloud_link(link)

        # Loop and test on HTML result
#        for file in os.scandir('.'):
#            if(file.name.endswith('.html')):
#                html_file = open(file.path, "r")
#                html = html_file.read()
#                html_file.close()

#                for link in extract_link_from_html(html):
#                    assert is_valid_link(link)

        # Clean up tmp directory
        for file in os.scandir("."):
            os.remove(file)
        os.chdir("..")
        os.rmdir("./tmpdir")
