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
"""Represents an issue found by a fuzzer"""

import logging

logger = logging.getLogger(name=__name__)
logger.setLevel(logging.INFO)


class Bug:
    """Holds data about a given bug found by fuzzers."""
    def __init__(
        self,
        source_file: str,
        source_line: str,
        function_name: str,
        fuzzer_name: str,
        description: str,
        bug_type: str
    ) -> None:
        self.source_file = source_file
        self.source_line = source_line
        self.function_name = function_name
        self.fuzzer_name = fuzzer_name
        self.description = description
        self.bug_type = bug_type
