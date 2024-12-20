# Copyright 2024 Fuzz Introspector Authors
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
"""APIs that make it easy to access frontend analysis."""

import logging

from fuzz_introspector.frontends import (frontend_c, frontend_cpp, frontend_go,
                                         frontend_jvm)

logger = logging.getLogger(name=__name__)


def analyse_source_file(code: bytes, language: str):
    """Runs frontend analysis on a code snippet.

    The code snippet should correspond to what you'd normally find in
    a source file, e.g. a number of functions, include statements and so
    on.

    Returns a frontend Source code module if successful and None otherwise."""

    if language == 'c':
        return frontend_c.analyse_source_code(code)
    elif language == 'cpp':
        return frontend_cpp.analyse_source_code(code)
    elif language == 'go':
        return frontend_go.analyse_source_code(code)
    elif language == 'jvm':
        return frontend_jvm.analyse_source_code(code)
    else:
        logger.info('Language %s not supported', language)
    return None
