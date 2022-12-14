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
"""Analysis for synthesizing fuzz drivers"""

import logging

from typing import (
    Dict,
    List,
    Tuple,
)

from fuzz_introspector import analysis
from fuzz_introspector import html_helpers
from fuzz_introspector.datatypes import (
    project_profile,
    fuzzer_profile,
    function_profile,
)
from fuzz_introspector.analyses import optimal_targets

logger = logging.getLogger(name=__name__)


class DriverContents:
    def __init__(self):
        self.source_code: str = ""
        self.target_fds: List[function_profile.FunctionProfile] = list()


class Analysis(analysis.AnalysisInterface):
    name: str = "FuzzDriverSynthesizerAnalysis"
    json_string_result: str = "[]"

    def __init__(self) -> None:
        pass

    @classmethod
    def get_name(cls):
        return cls.name

    @classmethod
    def get_json_string_result(cls):
        return cls.json_string_result

    @classmethod
    def set_json_string_result(cls, json_string):
        cls.json_string_result = json_string

    def analysis_func(
        self,
        toc_list: List[Tuple[str, str, int]],
        tables: List[str],
        proj_profile: project_profile.MergedProjectProfile,
        profiles: List[fuzzer_profile.FuzzerProfile],
        basefolder: str,
        coverage_url: str,
        conclusions: List[html_helpers.HTMLConclusion],
        fuzz_targets=None
    ) -> str:
        logger.info(f" - Running analysis {Analysis.get_name()}")
        html_string = ""
        html_string += "<div class=\"report-box\">"
        html_string += html_helpers.html_add_header_with_link(
            "Fuzz driver synthesis",
            1,
            toc_list
        )
        html_string += "<div class=\"collapsible\">"

        if fuzz_targets is None or len(fuzz_targets) == 0:
            A1 = optimal_targets.Analysis()

            _, optimal_target_functions = A1.iteratively_get_optimal_targets(
                proj_profile
            )
            fuzz_targets = optimal_target_functions

        target_codes: Dict[str, DriverContents] = dict()

        fuzzer_code = "#include \"ada_fuzz_header.h\"\n"
        fuzzer_code += "\n"
        fuzzer_code += "int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n"
        fuzzer_code += "  af_safe_gb_init(data, size);\n\n"

        var_idx = 0
        for tfd in fuzz_targets:
            code = ""
            code_var_decl = ""
            var_order = []
            for arg_type in tfd.arg_types:
                arg_type = arg_type.replace(" ", "")
                if arg_type == "char**":
                    code_var_decl += "  char **new_var%d = af_get_double_char_p();\n" % var_idx
                    # We dont want the below line but instead we want to ensure
                    # we always return something valid.
                    var_order.append("new_var%d" % var_idx)
                    var_idx += 1
                elif arg_type == "char*":
                    code_var_decl += "  char *new_var%d = ada_safe_get_char_p();\n" % var_idx
                    var_order.append("new_var%d" % var_idx)
                    var_idx += 1
                elif arg_type == "int":
                    code_var_decl += "  int new_var%d = ada_safe_get_int();\n" % var_idx
                    var_order.append("new_var%d" % var_idx)
                    var_idx += 1
                elif arg_type == "int*":
                    code_var_decl += "  int *new_var%d = af_get_int_p();\n" % var_idx
                    var_order.append("new_var%d" % var_idx)
                    var_idx += 1
                elif "struct" in arg_type and "*" in arg_type and "**" not in arg_type:
                    code_var_decl += "  %s new_var%d = calloc(sizeof(%s), 1);\n" % (
                        arg_type.replace(".", " "),
                        var_idx,
                        arg_type.replace(".", " ").replace("*", ""))
                    var_order.append("new_var%d" % var_idx)
                    var_idx += 1
                else:
                    code_var_decl += "  UNKNOWN_TYPE unknown_%d;\n" % var_idx
                    var_order.append("unknown_%d" % var_idx)
                    var_idx += 1

            # Now add the function call.
            code += "  /* target %s */\n" % tfd.function_name
            code += code_var_decl
            code += "  %s(" % tfd.function_name
            for idx in range(len(var_order)):
                code += var_order[idx]
                if idx < (len(var_order) - 1):
                    code += ", "
            code += ");\n"
            code += "\n"
            if tfd.function_source_file not in target_codes:
                target_codes[tfd.function_source_file] = DriverContents()

            target_codes[tfd.function_source_file].source_code += code
            target_codes[tfd.function_source_file].target_fds.append(tfd)

            logger.info(". Done")

        final_fuzzers: Dict[str, DriverContents] = dict()
        for filename in target_codes:
            file_fuzzer_code = fuzzer_code
            file_fuzzer_code += target_codes[filename].source_code
            file_fuzzer_code += "  af_safe_gb_cleanup();\n"
            file_fuzzer_code += "}\n"

            final_fuzzers[filename] = DriverContents()
            final_fuzzers[filename].source_code = file_fuzzer_code
            final_fuzzers[filename].target_fds = target_codes[filename].target_fds

        logger.info("Synthesizing drivers for the following optimal functions: { %s }" % (
            str([f.function_name for f in fuzz_targets])))

        # Create the necessary HTML code for displaying the fuzz drivers
        html_string += html_helpers.html_add_header_with_link("New fuzzers", 3, toc_list)
        html_string += "<p>The below fuzzers are templates and suggestions for how " \
                       "to target the set of optimal functions above</p>"

        for filename in final_fuzzers:
            html_string += html_helpers.html_add_header_with_link(
                str(filename.split("/")[-1]),
                4,
                toc_list
            )
            html_string += f"<b>Target file:</b>{filename}<br>"
            all_functions = ", ".join(
                [f.function_name for f in final_fuzzers[filename].target_fds]
            )
            html_string += f"<b>Target functions:</b> {all_functions}"
            html_string += (
                f"<pre><code class='language-clike'>"
                f"{final_fuzzers[filename].source_code}"
                f"</code></pre><br>"
            )

        html_string += "</div>"  # .collapsible
        html_string += "</div>"  # report-box
        logger.info(f" - Completed analysis {Analysis.get_name()}")

        return html_string
