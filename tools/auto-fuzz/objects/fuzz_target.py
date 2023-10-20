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
import yaml
import itertools

from typing import List, Any


class FuzzTarget:
    function_target: str
    exceptions_to_handle: List[str]
    fuzzer_source_code: str
    variables_to_add: List[Any]
    imports_to_add: List[str]
    heuristics_used: List[str]

    def __init__(self):
        self.function_target = ""
        self.exceptions_to_handle = []
        self.fuzzer_source_code = ""
        self.variables_to_add = []
        self.imports_to_add = []
        self.heuristics_used = []

    def __dict__(self):
        return {"function": self.function_target}

    def to_json(self):
        return self.function_target

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
