# Copyright 2023 Fuzz Introspector Authors
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
import shutil
import logging
import datetime
import requests
from typing import Optional, List

import lxml.html
from lxml import etree

sys.path.insert(0, '../../src/')
from fuzz_introspector import analysis, exceptions

CORRELATION_FILENAME = "exe_to_fuzz_introspector_logs.yaml"
BASE_PROJ_DIR = "workdir-"


def get_date_at_offset_as_str(day_offset=-1):
    datestr = (datetime.date.today() +
               datetime.timedelta(day_offset)).strftime("%Y%m%d")
    return datestr


def get_project_url(project_name, day_offset=-1):
    base_url = 'https://storage.googleapis.com/oss-fuzz-introspector/{0}/inspector-report/{1}/'
    datestr = get_date_at_offset_as_str(day_offset)
    project_url = base_url.format(project_name, datestr)
    return project_url


def project_exists_in_db(project_name, day_offset=-1) -> bool:
    """Returns whether the project exists in the fuzz introspector DB"""
    project_url = get_project_url(project_name,
                                  day_offset) + "fuzz_report.html"
    r = requests.get(project_url)
    return r.ok


def download_project_introspector_artifacts(project_name,
                                            dst_path,
                                            day_offset=-1):
    """For a given project, will download the specific fuzz introspector
    artifacts from the fuzz introspecto DB.
    """
    project_url = get_project_url(project_name, day_offset)
    CORRELATION_URL = project_url + CORRELATION_FILENAME
    project_report_url = project_url + "fuzz_report.html"

    r = requests.get(project_report_url)
    if not r.ok:
        print(f"Could not find a report: {project_report_url}")
        return False

    html_doc = lxml.html.document_fromstring(r.text)
    try:
        metadata_section = html_doc.get_element_by_id('Metadata-section')
    except KeyError:
        return False
    table = metadata_section.find_class('cell-border')
    e3 = table[-1].find_class('tbody')
    for url in table[-1].iterlinks():
        r = requests.get(project_url + url[2])
        if not r.ok:
            raise Exception("Failed to download file: %s" %
                            (project_url + url[2]))

        fpath = os.path.join(dst_path, url[2])
        with open(fpath, 'w') as f:
            f.write(r.text)

    # Check if there is a correlation file.
    r = requests.get(CORRELATION_URL)
    if r.ok:
        fpath = os.path.join(dst_path, CORRELATION_FILENAME)
        with open(fpath, 'w') as f:
            f.write(r.text)
    return True


def run_fuzz_introspector_on_dir(
        artifact_dir) -> Optional[analysis.IntrospectionProject]:
    """Runs introspector on the files in artifact_dir."""
    try:
        introspector_proj = analysis.IntrospectionProject(
            language='c-cpp', target_folder=artifact_dir, coverage_url="")
        introspector_proj.load_data_files(correlation_file="")
    except exceptions.FuzzIntrospectorError:
        return None
    return introspector_proj


def get_next_workdir():
    max_idx = -1
    for possible_dir in os.listdir("."):
        if os.path.isdir(possible_dir):
            try:
                idx = int(possible_dir.replace(BASE_PROJ_DIR, ""))
                max_idx = max(idx, max_idx)
            except:
                continue
    max_idx += 1
    return BASE_PROJ_DIR + str(max_idx)


def get_all_reports(project_names: List[str],
                    days_to_analyse=10,
                    interval_size=10):
    for project in project_names:
        complexities = []
        for i in range(1, days_to_analyse):
            day_offset = 0 - (i * interval_size)
            date_as_str = get_date_at_offset_as_str(day_offset)
            if not project_exists_in_db(project, day_offset):
                print("Does not exist in DB")
                continue

            workdir = get_next_workdir()
            os.mkdir(workdir)
            if not download_project_introspector_artifacts(
                    project, workdir, day_offset):
                print("Could not download artifacts")
                continue

            introspector_project = run_fuzz_introspector_on_dir(workdir)
            if introspector_project is None:
                continue

            yield (project, date_as_str, introspector_project)
