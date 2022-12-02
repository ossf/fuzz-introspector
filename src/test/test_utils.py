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
import os
import sys
import pytest

sys.path.append(os.path.dirname(os.path.realpath(__file__)) + "/../")

from fuzz_introspector import utils  # noqa: E402


@pytest.mark.parametrize(
    ("s1", "should_change"),
    [
        ("willnotnormalise", False),
        ("ksnfksjdgj", False),
        ("randomstring", False),
        ("this should change", True),
        ("This\tShuold\nAlso\nchange", True),
        ("should\tchange", True)
    ]
)
def test_normalise_str(s1: str, should_change: bool):
    changed = utils.normalise_str(s1) != s1
    assert changed == should_change


@pytest.mark.parametrize(
    ("strs", "expected"),
    [
        (
            [
                "the_prefix_a",
                "the_prefix_b",
                "the_prefix_c"
            ],
            ""
        ),
        (
            [
                "/src/project_name/dir1/file1.c",
                "/src/project_name/dir1/file2.c",
                "/src/project_name/dir2/README.md",
            ],
            "/src/project_name"
        ),
        (
            [
                "/src/project_name/file.c",
                "/src/project_name/file.c",
            ],
            "/src/project_name/file.c"
        )
    ]
)
def test_longest_common_prefix(strs: str, expected: str):
    longest_prefix = utils.longest_common_prefix(strs)
    assert longest_prefix == expected


@pytest.mark.parametrize(
    ('coverage_url', 'fuzz_target', 'res', 'lang'),
    [
        (
            'https://storage.googleapis.com/oss-fuzz-coverage/elfutils/reports/20221110/linux',  # noqa: E501
            'fuzz-libelf',
            'https://storage.googleapis.com/oss-fuzz-coverage/elfutils/reports-by-target/20221110/fuzz-libelf/linux',  # noqa: E501
            'c-cpp'
        ),
        (
            'https://storage.googleapis.com/oss-fuzz-coverage/util-linux/reports/20221110/linux',  # noqa: E501
            'test_last_fuzz',
            'https://storage.googleapis.com/oss-fuzz-coverage/util-linux/reports-by-target/20221110/test_last_fuzz/linux',  # noqa: E501
            'c-cpp'
        ),
    ]
)
def test_get_target_coverage_url(coverage_url: str, fuzz_target: str, res: str, lang: str):
    # Use environment as set by OSS-Fuzz.
    os.environ['FUZZ_INTROSPECTOR'] = "1"
    assert utils.get_target_coverage_url(coverage_url, fuzz_target, lang) == res
    del os.environ['FUZZ_INTROSPECTOR']


@pytest.mark.parametrize(
    ('cov_url', 'source_file', 'lineno', 'function_name', 'target_lang', 'temp_file', 'expect'),
    [
        (
            'https://coverage-url.com/',
            'fuzzlib/fuzzlib.c',
            '13',
            'name',
            'c-cpp',
            None,
            'https://coverage-url.com/fuzzlib/fuzzlib.c.html#L13'
        ),
        (
            'https://coverage-url.com/',
            'Class',
            '13',
            'name',
            'python',
            None,
            '#'
        ),
        (
            'https://coverage-url.com/',
            'Class',
            '13',
            'name',
            'python',
            '''{
                 "format":2,
                 "version":"6.5.0",
                 "globals":"Test",
                 "files":{
                     "Test":{
                         "hash":"Test",
                         "index":{
                             "relative_filename":"/src/fuzz_parse.py"
                         }
                     }
                 }
            }''',
            '#'
        ),
        (
            'https://coverage-url.com/',
            'Class',
            '13',
            'fuzz_parse',
            'python',
            '''{
                 "format":2,
                 "version":"6.5.0",
                 "globals":"Test",
                 "files":{
                     "Test":{
                         "hash":"Test",
                         "index":{
                             "relative_filename":"/src/fuzz_parse.py"
                         }
                     }
                 }
            }''',
            'https://coverage-url.com/Test.html#t13'
        ),
        (
            'https://coverage-url.com/',
            'Class',
            '13',
            'abc.def.fuzz_parse',
            'python',
            '''{
                 "format":2,
                 "version":"6.5.0",
                 "globals":"Test",
                 "files":{
                     "Test":{
                         "hash":"Test",
                         "index":{
                             "relative_filename":"/src/abc/def.py"
                         }
                     }
                 }
            }''',
            'https://coverage-url.com/Test.html#t13'
        ),
        (
            'https://coverage-url.com/',
            'Class',
            '13',
            'name',
            'jvm',
            None,
            'https://coverage-url.com/default/Class.java.html#L13'
        ),
        (
            'https://coverage-url.com/',
            'Package.Class$Subclass',
            '13',
            'name',
            'jvm',
            None,
            'https://coverage-url.com/Package/Class.java.html#L13'
        ),
        (
            'https://coverage-url.com/',
            'Test.Package.Class',
            '13',
            'name',
            'jvm',
            None,
            'https://coverage-url.com/Test.Package/Class.java.html#L13'
        ),
        (
            'https://coverage-url.com/',
            'fuzzlib/fuzzlib.c',
            '13',
            'name',
            'abcde',
            None,
            '#'
        )
    ]
)
def test_resolve_coverage_link(
    cov_url: str,
    source_file: str,
    lineno: int,
    function_name: str,
    target_lang: str,
    temp_file: str,
    expect: str
):
    """Basic test of coverage URL for all lang"""
    if (temp_file is not None):
        # Create temp html_status.json for python coverage link
        with open('temp_html_status.json', 'w+') as f:
            f.write(temp_file)

    actual = utils.resolve_coverage_link(
        cov_url,
        source_file,
        lineno,
        function_name,
        target_lang
    )
    assert expect == actual

    if (temp_file is not None):
        # Remove temp html_status.json file
        os.remove('temp_html_status.json')
