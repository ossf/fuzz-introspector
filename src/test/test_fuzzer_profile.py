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
"""Test datatypes/fuzzer_profile.py"""

import os
import sys
import pytest

sys.path.append(os.path.dirname(os.path.realpath(__file__)) + "/../")

from fuzz_introspector.datatypes import fuzzer_profile  # noqa: E402


@pytest.fixture
def sample_cfg1():
    """Fixture for a sample (shortened paths) calltree"""
    cfg_str = """Call tree
LLVMFuzzerTestOneInput /src/wuffs/fuzz/c/fuzzlib/fuzzlib.c linenumber=-1
  llvmFuzzerTestOneInput /src/wuffs/fuzz/c/../fuzzlib/fuzzlib.c linenumber=93
    jenkins_hash_u32 /src/wuffs/fuzz/c/std/../fuzzlib/fuzzlib.c linenumber=67
    jenkins_hash_u32 /src/wuffs/fuzz/c/std/../fuzzlib/fuzzlib.c linenumber=68
    wuffs_base__ptr_u8__reader /src/wuffs/fuzz/...-snapshot.c linenumber=72
    fuzz /src/wuffs/fuzz/c/std/bmp_fuzzer.c linenumber=74"""
    return cfg_str


def base_cpp_profile(tmpdir, sample_cfg1, fake_yaml_func_elem):
    # Write the CFG
    cfg_path = os.path.join(tmpdir, "test_file.data")
    with open(cfg_path, "w") as f:
        f.write(sample_cfg1)

    fake_frontend_yaml = {
        "Fuzzer filename": "/src/wuffs/fuzz/c/fuzzlib/fuzzlib.c",
        "All functions": {
            "Elements": fake_yaml_func_elem
        }
    }

    fp = fuzzer_profile.FuzzerProfile(
        os.path.join(tmpdir, "test_file.data"),
        fake_frontend_yaml,
        "c-cpp"
    )

    return fp


def test_reaches_file(tmpdir, sample_cfg1):
    """Basic test for reaches file"""
    fp = base_cpp_profile(tmpdir, sample_cfg1, [])
    fp._set_file_targets()

    # Ensure set_file_target analysis has been done
    assert len(fp.file_targets) != 0

    assert not fp.reaches_file('fuzzlib.c')
    assert fp.reaches_file('/src/wuffs/fuzz/c/fuzzlib/fuzzlib.c')
    assert fp.reaches_file('/src/wuffs/fuzz/...-snapshot.c')


def test_reaches_file_with_refine_path(tmpdir, sample_cfg1):
    """test for reaches file with refine path"""
    fp = base_cpp_profile(tmpdir, sample_cfg1, [])
    fp._set_file_targets()

    # Ensure set_file_target analysis has been done
    assert len(fp.file_targets) != 0

    fp.refine_paths('/src/wuffs/fuzz/c')

    assert not fp.reaches_file('fuzzlib.c')
    assert not fp.reaches_file('/src/wuffs/fuzz/c/fuzzlib/fuzzlib.c')
    assert fp.reaches_file('/src/wuffs/fuzz/...-snapshot.c')
    assert fp.reaches_file('/std/../fuzzlib/fuzzlib.c')


def generate_temp_elem(name, func):
    return {
        "functionName": name,
        "functionsReached": func,
        "functionSourceFile": None,
        "linkageType": None,
        "functionLinenumber": None,
        "returnType": None,
        "argCount": None,
        "argTypes": None,
        "argNames": None,
        "BBCount": None,
        "ICount": None,
        "EdgeCount": None,
        "CyclomaticComplexity": None,
        "functionUses": None,
        "functionDepth": None,
        "constantsTouched": None,
        "BranchProfiles": [],
        "Callsites": []
    }


def test_reaches_func(tmpdir, sample_cfg1):
    """test for reaches file with refine path"""
    elem = [
        generate_temp_elem(
            "LLVMFuzzerTestOneInput",
            ["abc", "def", "ghi"]
        ),
        generate_temp_elem(
            "TestOneInput",
            ["jkl", "mno", "pqr"]
        ),
        generate_temp_elem(
            "Random",
            ["stu", "vwx", "yz"]
        )
    ]

    fp = base_cpp_profile(tmpdir, sample_cfg1, elem)
    fp._set_all_reached_functions()

    # Ensure set_all_reached_functions analysis has been done
    assert len(fp.functions_reached_by_fuzzer) != 0

    assert fp.reaches_func('abc')
    assert not fp.reaches_func('stu')
    assert not fp.reaches_func('mno')
