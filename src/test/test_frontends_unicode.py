# Copyright 2025 Fuzz Introspector Authors
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
"""Unit testing script for the C frontend"""

from fuzz_introspector.frontends import oss_fuzz  # noqa: E402


def test_unicode_error_c():
    try:
        project, _ = oss_fuzz.analyse_folder(
            language='c',
            directory='src/test/data/source-code/c/unicode-error/',
            entrypoint='LLVMFuzzerTestOneInput',
        )
    except UnicodeDecodeError:
        assert False


def test_unicode_error_cpp():
    try:
        project, _ = oss_fuzz.analyse_folder(
            language='c++',
            directory='src/test/data/source-code/cpp/unicode-error/',
            entrypoint='LLVMFuzzerTestOneInput',
        )
    except UnicodeDecodeError:
        assert False


def test_unicode_error_jvm():
    try:
        project, _ = oss_fuzz.analyse_folder(
            language='jvm',
            directory='src/test/data/source-code/jvm/unicode-error/',
            entrypoint='fuzzerTestOneInput',
        )
    except UnicodeDecodeError:
        assert False


def test_unicode_error_rust():
    try:
        project, _ = oss_fuzz.analyse_folder(
            language='rust',
            directory='src/test/data/source-code/rust/unicode-error/',
        )
    except UnicodeDecodeError:
        assert False


def test_unicode_error_go():
    try:
        project, _ = oss_fuzz.analyse_folder(
            language='go',
            directory='src/test/data/source-code/go/unicode-error/'
        )
    except UnicodeDecodeError:
        assert False
