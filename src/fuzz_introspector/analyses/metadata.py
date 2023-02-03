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
"""Analysis for showing metadata"""

import os
import logging

from typing import (
    List,
    Tuple,
)

from fuzz_introspector import analysis
from fuzz_introspector import html_helpers
from fuzz_introspector.datatypes import (
    project_profile,
    fuzzer_profile,
)

logger = logging.getLogger(name=__name__)


class MetadataAnalysis(analysis.AnalysisInterface):
    name: str = "MetadataAnalysis"

    def __init__(self) -> None:
        self.json_string_result = "[]"

    @classmethod
    def get_name(cls):
        return cls.name

    def get_json_string_result(self):
        return self.json_string_result

    def set_json_string_result(self, json_string):
        self.json_string_result = json_string

    def analysis_func(self, toc_list: List[Tuple[str, str,
                                                 int]], tables: List[str],
                      project_profile: project_profile.MergedProjectProfile,
                      profiles: List[fuzzer_profile.FuzzerProfile],
                      basefolder: str, coverage_url: str,
                      conclusions: List[html_helpers.HTMLConclusion]) -> str:
        logger.info(f" - Running analysis {self.get_name()}")

        html_string = ""
        html_string += "<div class=\"report-box\">"
        html_string += html_helpers.html_add_header_with_link(
            "Metadata section", 1, toc_list)
        html_string += "<div class=\"collapsible\">"
        html_string += """<p>This sections shows the raw data that is used
        to produce this report. This is mainly used for further processing
        and developer debugging.</p>
        """
        html_string += "<p>"
        tables.append(f"myTable{len(tables)}")
        html_string += html_helpers.html_create_table_head(
            tables[-1], [("Fuzzer", ""), ("Calltree file", ""),
                         ("Program data file", ""), ("Coverage file", "")])
        for profile in profiles:
            if profile.coverage is None:
                continue
            base_datafile = os.path.basename(profile.introspector_data_file)
            full_yaml_path = profile.introspector_data_file + ".yaml"
            base_yamlfile = os.path.basename(full_yaml_path)
            coverage_file_link_str = ""
            for idx in range(len(profile.coverage.coverage_files)):
                cov_prof = profile.coverage.coverage_files[idx]
                cov_prof = os.path.basename(cov_prof)
                coverage_file_link_str += f"<a href=\"{cov_prof}\">{cov_prof}</a>"
                if idx < len(profile.coverage.coverage_files) - 1:
                    coverage_file_link_str += ","

            html_string += html_helpers.html_table_add_row([
                profile.identifier,
                f"<a href=\"{base_datafile}\">{base_datafile}</a>",
                f"<a href=\"{base_yamlfile}\">{base_yamlfile}</a>",
                f"{coverage_file_link_str}"
            ])

        html_string += "</p>"

        html_string += "</div>"  # .collapsible
        html_string += "</div>"  # report-box

        logger.info(f" - Completed analysis {self.get_name()}")

        return html_string
