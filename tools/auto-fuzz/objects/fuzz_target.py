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
import json
import yaml
import itertools

from typing import List, TypedDict, Any


class ExtraSourceCode(TypedDict):
    private_field: str
    fuzzer_file_prepare: str
    fuzzer_init: str
    fuzzer_tear_down: str


class FuzzTarget:
    function_class: str
    function_name: str
    fuzzer_source_code: str
    function_target: str
    exceptions_to_handle: List[str]
    variables_to_add: List[Any]
    imports_to_add: List[str]
    heuristics_used: List[str]
    class_field_list: List[str]
    extra_source_code: ExtraSourceCode

    def __init__(self):
        self.function_class = ""
        self.function_name = ""
        self.fuzzer_source_code = ""
        self.function_target = ""
        self.exceptions_to_handle = []
        self.variables_to_add = []
        self.imports_to_add = []
        self.heuristics_used = []
        self.class_field_list = []
        self.extra_source_code = {
            "private_field": "",
            "fuzzer_file_prepare": "",
            "fuzzer_init": "",
            "fuzzer_tear_down": ""
        }
        self.is_openai = False
        self.openai_source = ""

    def to_json(self):
        if self.is_openai:
            return json.dumps({
                'source': self.openai_source,
                'is_openai': True
            })

        return json.dumps({
            "function_class": self.function_class,
            "function_name": self.function_name,
            "fuzzer_source_code": self.fuzzer_source_code,
            "function_target": self.function_target,
            "exceptions_to_handle": self.exceptions_to_handle,
            "variables_to_add": self.variables_to_add,
            "imports_to_add": self.imports_to_add,
            "heuristics_used": self.heuristics_used,
            "class_field_list": self.class_field_list,
            "extra_source_code": self.extra_source_code,
            'is_openai': False
        })

    def from_json(self, json_str):
        obj = json.loads(json_str)
        print("obj: %s" % (obj))
        self.is_openai = obj['is_openai']
        if self.is_openai:
            self.openai_source = obj['source']
            return

        self.function_class = obj['function_class']
        self.function_name = obj['function_name']
        self.fuzzer_source_code = obj['fuzzer_source_code']
        self.function_target = obj['function_target']
        self.exceptions_to_handle = obj['exceptions_to_handle']
        self.variables_to_add = obj['variables_to_add']
        self.imports_to_add = obj['imports_to_add']
        self.heuristics_used = obj['heuristics_used']
        self.class_field_list = obj['class_field_list']
        self.extra_source_code = obj['extra_source_code']

    def __str__(self):
        return self.function_target

    def __name__(self):
        return "function"

    def generate_patched_fuzzer(self, filename):
        """Patches the fuzzer in `filename`.
        Performs three actions:
        1) Adds the imports necessary for the fuzzer.
        2) Adds the variables that should be seeded with fuzzing data.
        3) Adds the source code of the fuzzer.
        """
        # Dummy function
        return
