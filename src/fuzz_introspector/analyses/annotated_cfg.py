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
"""Creates an annotated CFG, focusing on only a subset of the CFG atm."""

import os
import logging
import json

from typing import (Any, Dict, List)

from fuzz_introspector import analysis
from fuzz_introspector import utils
from fuzz_introspector import cfg_load
from fuzz_introspector import json_report
from fuzz_introspector import html_helpers
from fuzz_introspector.datatypes import project_profile, fuzzer_profile

logger = logging.getLogger(name=__name__)


class FuzzAnnotatedCFG(analysis.AnalysisInterface):
    name: str = "AnnotatedCFG"

    def __init__(self) -> None:
        logger.info("Creating annotated CFG")
        self.json_string_result = ""
        self.json_results: Dict[str, Any] = dict()
        self.dump_files = False

    @classmethod
    def get_name(cls):
        return cls.name

    def get_json_string_result(self):
        return json.dumps(self.json_results)

    def set_json_string_result(self, json_string):
        self.json_string_result = json_string

    def analysis_func(self,
                      table_of_contents: html_helpers.HtmlTableOfContents,
                      tables: List[str],
                      proj_profile: project_profile.MergedProjectProfile,
                      profiles: List[fuzzer_profile.FuzzerProfile],
                      basefolder: str, coverage_url: str,
                      conclusions: List[html_helpers.HTMLConclusion]) -> str:
        """
        Creates the HTML of the calltree. Returns the HTML as a string.
        """
        logger.info("Creating annotated CFGs")

        for profile in profiles:
            logger.info("Analysing: %s" % (profile.identifier))
            destinations = []
            src_file = None
            is_first = True
            # We must haev a high number here initially, to trigger the first
            # catch.
            callsite_stack = dict()
            for callsite in cfg_load.extract_all_callsites(
                    profile.fuzzer_callsite_calltree):

                # Set the stack
                callsite_stack[callsite.depth] = callsite

                if is_first:
                    src_file_fd = self.get_profile_sourcefile(
                        profile, callsite.dst_function_name)
                    if src_file_fd is not None:
                        src_file = src_file_fd.function_source_file
                        is_first = False
                        continue
                    continue

                parent_callsite = callsite_stack[callsite.depth - 1]

                dst_fd = self.get_profile_sourcefile_merged(
                    proj_profile, callsite.dst_function_name)
                if dst_fd is None:
                    dst_fd = self.get_profile_sourcefile_merged(
                        proj_profile,
                        "[%s].%s" % (callsite.dst_function_source_file,
                                     callsite.dst_function_name))

                par_fd = self.get_profile_sourcefile_merged(
                    proj_profile, parent_callsite.dst_function_name)
                if par_fd is None:
                    par_fd = self.get_profile_sourcefile_merged(
                        proj_profile,
                        "[%s].%s" % (parent_callsite.dst_function_source_file,
                                     parent_callsite.dst_function_name))

                # To be a top level target a callsite should:
                # 1.0) Not be in the fuzzer source file and one of the following:
                #    1a) have parent callsite be in the fuzzer, i.e. transition
                #        from files.
                #    1b) Have calldepth 1 (i.e. directly from LLVMFuzzerTestOneInput),
                #        since we know parent then is in fuzzer source file.
                cond1 = dst_fd is not None and dst_fd.function_source_file != src_file
                cond2 = (par_fd is not None and par_fd.function_source_file
                         == src_file) or callsite.depth == 1
                if (cond1 and cond2):
                    destinations.append({
                        'function-name':
                        dst_fd.function_name,
                        'raw-function-name':
                        dst_fd.raw_function_name,
                        'source-file':
                        os.path.normpath(dst_fd.function_source_file),
                        'cyclomatic-complexity':
                        dst_fd.cyclomatic_complexity,
                        'accummulated-cyclomatic-complexity':
                        dst_fd.total_cyclomatic_complexity,
                        'return-type':
                        dst_fd.return_type,
                        'arg-types':
                        dst_fd.arg_types,
                        'arg-names':
                        dst_fd.arg_names,
                    })

            if proj_profile.target_lang == 'jvm':
                src_file = self.find_jvm_source(profile.fuzzer_source_file)

            if src_file is None:
                src_file = "Did-not-find-sourcefile"
            self.json_results[profile.identifier] = {
                'destinations': destinations,
                'src_file': os.path.normpath(src_file)
            }

        # Write the results to the json report
        json_report.add_analysis_json_str_as_dict_to_report(
            self.get_name(), self.get_json_string_result())
        return ""

    def get_profile_sourcefile(self, profile, func_name):
        dst_options = [
            func_name,
            utils.demangle_cpp_func(func_name),
            utils.demangle_rust_func(func_name),
        ]
        for dst in dst_options:
            try:
                fd = profile.dst_to_fd_cache[dst]
                return fd
            except KeyError:
                pass
            try:
                fd = profile.dst_to_fd_cache[utils.normalise_str(dst)]
                return fd
            except KeyError:
                pass
        return None

    def get_profile_sourcefile_merged(self, merged_profile, func_name):
        dst_options = [
            func_name,
            utils.demangle_cpp_func(func_name),
            utils.demangle_rust_func(func_name),
        ]
        for dst in dst_options:
            try:
                fd = merged_profile.dst_to_fd_cache[dst]
                return fd
            except KeyError:
                pass
            try:
                fd = merged_profile.dst_to_fd_cache[utils.normalise_str(dst)]
                return fd
            except KeyError:
                pass
        return None

    def find_jvm_source(self, class_name):
        """Locate the source file in $SRC on a full qualified class name."""
        src_dir = os.environ.get('SRC', None)
        if not src_dir or not class_name:
            return None

        class_name = class_name.split('.')[-1]
        for root, _, files in os.walk(src_dir):
            for file in files:
                if file.endswith('.class'):
                    continue
                if file.rsplit('.', 1)[0] == class_name:
                    return os.path.join(root, file)

        return None
