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

import json
import logging
import os

from typing import (
    List,
    Tuple,
)

from fuzz_introspector import analysis
from fuzz_introspector import constants
from fuzz_introspector import html_helpers
from fuzz_introspector import utils
from fuzz_introspector.analyses import calltree_analysis as cta
from fuzz_introspector.datatypes import (
    project_profile,
    fuzzer_profile,
)

logger = logging.getLogger(name=__name__)


class Analysis(analysis.AnalysisInterface):
    def __init__(self) -> None:
        self.display_html = False

    @staticmethod
    def get_name():
        return "FuzzEngineInputAnalysis"

    def analysis_func(
        self,
        toc_list: List[Tuple[str, str, int]],
        tables: List[str],
        project_profile: project_profile.MergedProjectProfile,
        profiles: List[fuzzer_profile.FuzzerProfile],
        basefolder: str,
        coverage_url: str,
        conclusions: List[html_helpers.HTMLConclusion]
    ) -> str:
        logger.info(f" - Running analysis {Analysis.get_name()}")

        if not self.display_html:
            toc_list = []

        html_string = ""
        html_string += "<div class=\"report-box\">"
        html_string += html_helpers.html_add_header_with_link(
            "Fuzz engine guidance",
            1,
            toc_list
        )
        html_string += "<div class=\"collapsible\">"
        html_string += "<p>This sections provides heuristics that can be used as input " \
                       "to a fuzz engine when running a given fuzz target. The current " \
                       "focus is on providing input that is usable by libFuzzer.</p>"

        for profile_idx in range(len(profiles)):
            logger.info(f"Generating input for {profiles[profile_idx].identifier}")
            html_string += html_helpers.html_add_header_with_link(
                profiles[profile_idx].fuzzer_source_file,
                2,
                toc_list
            )

            # Create dictionary section
            html_string += self.get_dictionary_section(
                profiles[profile_idx],
                toc_list
            )

            html_string += "<br>"

            # Create focus function section
            html_string += self.get_fuzzer_focus_function_section(
                profiles[profile_idx],
                toc_list,
            )
        html_string += "</div>"  # .collapsible
        html_string += "</div>"  # report-box

        logger.info(f" - Completed analysis {Analysis.get_name()}")
        if not self.display_html:
            html_string = ""

        return html_string

    def get_dictionary(self, profile: fuzzer_profile.FuzzerProfile) -> str:
        """Extracts a fuzzer dictionary"""
        kn = 0
        dictionary_content = ""
        if profile.functions_reached_by_fuzzer is None:
            return ""

        for fn in profile.functions_reached_by_fuzzer:
            try:
                fp = profile.all_class_functions[fn]
            except Exception as e:
                logger.debug(e)
                continue
            for const in fp.constants_touched:
                dictionary_content += f"k{kn}=\"{const}\"\n"
                kn += 1
        return dictionary_content

    def get_dictionary_section(
        self,
        profile: fuzzer_profile.FuzzerProfile,
        toc_list: List[Tuple[str, str, int]]
    ) -> str:
        """
        Returns a HTML string with dictionary content, and adds the section
        link to the toc_list.
        """

        html_string = html_helpers.html_add_header_with_link(
            "Dictionary",
            3,
            toc_list
        )
        html_string += "<p>Use this with the libFuzzer -dict=DICT.file flag</p>"
        html_string += "<pre><code class='language-clike'>"
        html_string += self.get_dictionary(profile)
        html_string += "</code></pre>"
        return html_string

    def get_fuzzer_focus_function_section(
        self,
        profile: fuzzer_profile.FuzzerProfile,
        toc_list: List[Tuple[str, str, int]]
    ) -> str:
        """Returns HTML string with fuzzer focus function"""
        html_string = html_helpers.html_add_header_with_link(
            "Fuzzer function priority",
            3,
            toc_list
        )

        calltree_analysis = cta.Analysis()
        fuzz_blockers = calltree_analysis.get_fuzz_blockers(
            profile,
            max_blockers_to_extract=10
        )

        if len(fuzz_blockers) == 0:
            logger.info("Found no fuzz blockers and thus no focus function")
            return ""

        # Only succeed if we can get the name of the function in which the
        # fuzz blocker callsite resides.
        focus_functions = []
        for fuzz_blocker in fuzz_blockers:
            ffname = fuzz_blocker.src_function_name
            if ffname is not None and ffname not in focus_functions:
                focus_functions.append(
                    utils.demangle_cpp_func(ffname)
                )
                logger.info(f"Found focus function: {fuzz_blocker.src_function_name}")

        if len(focus_functions) == 0:
            return ""

        self.add_to_json_file(
            constants.ENGINE_INPUT_FILE,
            profile.identifier,
            "focus-functions",
            focus_functions
        )

        html_string += (
            f"<p>Use one of these functions as input to libfuzzer with flag: "
            f"-focus_function name </p>"
            f"<pre><code class='language-clike'>"
            f"-focus_function={focus_functions}"
            f"</code></pre><br>"
        )
        return html_string

    def add_to_json_file(
        self,
        json_file_path: str,
        fuzzer_name: str,
        key: str,
        val: List[str]
    ) -> None:
        # Create file if it does not exist
        if not os.path.isfile(json_file_path):
            json_data = dict()
        else:
            json_fd = open(json_file_path)
            json_data = json.load(json_fd)
            json_fd.close()
        if 'fuzzers' not in json_data:
            json_data['fuzzers'] = dict()

        if fuzzer_name not in json_data['fuzzers']:
            json_data['fuzzers'][fuzzer_name] = dict()

        json_data['fuzzers'][fuzzer_name][key] = val

        with open(json_file_path, 'w') as json_file:
            json.dump(json_data, json_file)
