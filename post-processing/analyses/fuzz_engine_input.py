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
"""Analysis for creating input consumed by a fuzzer, e.g. a dictionary"""

import logging

from typing import (
    List,
    Tuple,
)

import fuzz_analysis
import fuzz_data_loader
import fuzz_html_helpers

logger = logging.getLogger(name=__name__)


class FuzzEngineInputAnalysis(fuzz_analysis.AnalysisInterface):
    def __init__(self):
        self.name = "FuzzEngineInputAnalysis"

    def analysis_func(self,
                      toc_list: List[Tuple[str, str, int]],
                      tables: List[str],
                      project_profile: fuzz_data_loader.MergedProjectProfile,
                      profiles: List[fuzz_data_loader.FuzzerProfile],
                      basefolder: str,
                      coverage_url: str,
                      conclusions) -> str:
        logger.info(f" - Running analysis {self.name}")

        html_string = ""
        html_string += "<div class=\"report-box\">"
        html_string += fuzz_html_helpers.html_add_header_with_link(
            "Fuzz engine guidance", 1, toc_list)
        html_string += "<p>This sections provides heuristics that can be used as input " \
                       "to a fuzz engine when running a given fuzz target. The current " \
                       "focus is on providing input that is usable by libFuzzer.</p>"

        for profile_idx in range(len(profiles)):
            html_string += fuzz_html_helpers.html_add_header_with_link(
                "%s" % (profiles[profile_idx].fuzzer_source_file),
                2,
                toc_list)

            # Create dictionary section
            html_string += self.get_dictionary_section(
                profiles[profile_idx],
                toc_list
            )

            html_string += "<br>"

            # Create focus function section
            html_string += self.get_fuzzer_focus_function_section(
                profiles[profile_idx],
                toc_list
            )
        html_string += "</div>"  # report-box

        logger.info(f" - Completed analysis {self.name}")
        return html_string

    def get_dictionary(self, profile):
        """Extracts a fuzzer dictionary"""
        kn = 0
        dictionary_content = ""
        for fn in profile.functions_reached_by_fuzzer:
            fp = profile.all_class_functions[fn]
            for const in fp.constants_touched:
                dictionary_content += f"k{kn}=\"{const}\"\n"
                kn += 1
        return dictionary_content

    def get_dictionary_section(self, profile, toc_list):
        """
        Returns a HTML string with dictionary content, and adds the section
        link to the toc_list.
        """

        html_string = fuzz_html_helpers.html_add_header_with_link(
            "Dictionary",
            3,
            toc_list
        )
        html_string += "<p>Use this with the libFuzzer -dict=DICT.file flag</p>"
        html_string += "<pre><code class='language-clike'>"
        html_string += self.get_dictionary(profile)
        html_string += "</code></pre>"
        return html_string

    def get_fuzzer_focus_function_section(self, profile, toc_list):
        """Returns HTML string with fuzzer focus function"""
        html_string = fuzz_html_helpers.html_add_header_with_link(
            "Fuzzer function priority",
            3,
            toc_list
        )
        html_string += "<p>Use this as input to libfuzzer with flag: " \
                       "-focus_function=FUNC_NAME</p>"
        html_string += "<pre><code class='language-clike'>TBD</code></pre><br>"
        return html_string
