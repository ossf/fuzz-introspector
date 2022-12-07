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
import os
import sys

sys.path.append(os.path.dirname(os.path.realpath(__file__)) + "/../")

from fuzz_introspector import html_helpers  # noqa: E402


def test_gtag():
    header = html_helpers.html_get_header()
    assert "<!-- Google tag (gtag.js) -->" not in header

    os.environ["G_ANALYTICS_TAG"] = "FUZZINTRO123"

    header = html_helpers.html_get_header()
    assert "<!-- Google tag (gtag.js) -->" in header
    assert "FUZZINTRO123" in header
