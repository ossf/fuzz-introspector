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
"""Styling files for HTML reports."""
import os
import shutil

# All style files in the repository.
ALL_STYLE_FILES = [
    "clike.js", "prism.css", "prism.js", "styles.css", "custom.js",
    "calltree.js"
]

# Javascript files for main page.
MAIN_JS_FILES = ["prism.js", "clike.js", "custom.js"]

JAVASCRIPT_REMOTE_SCRIPTS = [
    "https://cdn.datatables.net/buttons/2.2.2/js/dataTables.buttons.min.js",
    "https://cdn.datatables.net/buttons/2.2.2/js/buttons.colVis.min.js"
]


def copy_style_files(dst: str) -> None:
    src_base_path = os.path.dirname(os.path.realpath(__file__))
    for style_file in ALL_STYLE_FILES:
        src_file = os.path.join(src_base_path, style_file)
        dst_file = os.path.join(dst, style_file)
        shutil.copy(src_file, dst_file)
