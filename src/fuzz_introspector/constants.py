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

import re

GIT_REPO = "https://github.com/ossf/fuzz-introspector"
GIT_BRANCH_URL = f"{GIT_REPO}/blob/main"

ENGINE_INPUT_FILE = "fuzz-introspector-engine-input.json"
SUMMARY_FILE = "summary.json"
ALL_FUNCTIONS_JSON = 'all-fuzz-introspector-functions.json'
ALL_JVM_CONSTRUCTOR_JSON = 'all-fuzz-introspector-jvm-constructor.json'
BRANCH_BLOCKERS_FILE = 'branch-blockers.json'
TEST_FILES_JSON = 'test-files.json'
ALL_SOURCE_FILES = 'all-files.json'

HTML_REPORT = "fuzz_report.html"

DEBUG_INFO_DUMP = "all_debug_info.json"

SAVED_SOURCE_FOLDER = 'source-code'

# Holds data about all functions in javascript, to ease loading of static
# website.
ALL_FUNCTION_JS = "all_functions.js"

FUZZER_TABLE_JS = "fuzzer_table_data.js"

# TODO: change the name of the following file to be something meaningful.
OPTIMAL_TARGETS_ALL_FUNCTIONS = "analysis_1.js"

# Global that may change.
# Indicates if files should be dumped.
should_dump_files = True

APP_EXIT_ERROR = 1
APP_EXIT_SUCCESS = 0

INPUT_BUG_FILE = "input_bugs.json"
JSON_REPORT_KEY_PROJECT = 'MergedProjectProfile'

# Color constants used for call trees. Composed of tuples,
# (min, max, color) where
# min and max construct an interval [min: max) (max non-inclusive)
# and this interval indicates how many times a callsite was hit. If a
# callsite is hit X times and X falls in the given interval then it will
# have the color of the tuple.
# - color is the string
# The hitcount is [min:max)
COLOR_CONSTANTS = [(0, 1, "red", "#ff0000"), (1, 10, "gold", "#ffd700"),
                   (10, 30, "yellow", "#ffff00"),
                   (30, 50, "greenyellow", "#adff2f"),
                   (50, 1000000000000, "lawngreen", "#7cfc00")]

BLOCKLISTED_FUNCTION_NAMES = re.compile(
    r'^__sanitizer|^llvm\.|^__assert|.*printf$')

# Use by SinkCoverageAnaylser in analyses/sink_analyser.py
# Integer constants to limit the maximum number of callpaths
# generated for each of the unreachable sink functions found
# in the target project.
SINK_FUNCTION_CALLPATH_MAX_COUNT = 2
