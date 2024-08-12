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
"""Module containing meta text for the webapp."""
import os

default_helper_text = """This page shows stats and data on open source fuzzing of the
projects integrated into OSS-Fuzz. The analysis is generated by
Fuzz Introspector, which is our tool for analysing the quality of
fuzzing for an open source project. The goal is to make the status
transparent and useful for developers and researchers to identify
if the code they use is properly analysed."""

default_page_base_title = """Open Source <br />
Fuzzing Introspection"""

default_page_main_name = "OSS-Fuzz"
default_page_main_url = "https://github.com/google/oss-fuzz"


def get_page_name():
    return os.getenv('FI_PAGE_MAIN_NAME', default_page_main_name)


def get_page_main_url():
    return os.getenv('FI_PAGE_MAIN_URL', default_page_main_url)


def get_page_summary():
    return os.getenv('FI_PAGE_SUMMARY', default_helper_text)


def get_page_base_title():
    return os.getenv('FI_PAGE_BASE_TITLE', default_page_base_title)