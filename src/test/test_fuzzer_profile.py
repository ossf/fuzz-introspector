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
import tempfile

sys.path.append(os.path.dirname(os.path.realpath(__file__)) + "/../")

from fuzz_introspector import code_coverage  # noqa: E402
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
        "c-cpp",
        cfg_content=sample_cfg1
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
        "functionSourceFile": '/src/wuffs/fuzz/c/fuzzlib/fuzzlib.c',
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


def generate_temp_covreport():
    sample_coverage = """
fuzzlib.c:Random:
  1|      110|int x0 = 32;
  2|      213|int x1 = 8;

fuzzlib.c:def:
  3|      0|int x0 = 25;
  4|      0|int x1 = 49;
  5|      0|int x2 = 55;

fuzzlib.c:TestOneInput:
  6|      0|int x0 = 55;
  7|      0|int x1 = 53;
  8|    113|int x2 = 29;

fuzzlib.c:vwx:
  9|      0|int x0 = 25;
 10|      0|int x1 = 10;

fuzzlib.c:jkl:
 15|      0|int x0 = 48;
 16|      0|int x1 = 10;

fuzzlib.c:abc:
 20|      0|int x0 = 6;
 21|      333|int x1 = 7;

fuzzlib.c:stu:
 22|      0|int x0 = 45;
 23|      0|int x1 = 93;
 24|      133|int x2 = 81;

fuzzlib.c:LLVMFuzzerTestOneInput:
 25|    409|int x0 = 27;
 26|      0|int x1 = 59;

fuzzlib.c:mno:
 27|      0|int x0 = 0;
 28|      0|int x1 = 1;
"""

    with tempfile.NamedTemporaryFile(delete=False, mode="w+", suffix='.covreport') as f:
        f.write(sample_coverage)
        f.flush()
        return f.name

    return None


def test_reaches_func(tmpdir, sample_cfg1):
    """test for reaches file with refine path"""
    elem = [
        generate_temp_elem(
            "LLVMFuzzerTestOneInput",
            ["abc", "def"]
        ),
        generate_temp_elem(
            "TestOneInput",
            ["jkl", "mno"]
        ),
        generate_temp_elem(
            "Random",
            ["stu", "vwx"]
        )
    ]

    # Statically reached functions
    fp = base_cpp_profile(tmpdir, sample_cfg1, elem)
    fp._set_all_reached_functions()

    # Ensure set_all_reached_functions analysis has been done
    assert len(fp.functions_reached_by_fuzzer) != 0

    assert fp.reaches_func('abc')
    assert not fp.reaches_func('stu')
    assert not fp.reaches_func('mno')

    # Runtime reached functions
    path = generate_temp_covreport()
    fp.coverage = code_coverage.load_llvm_coverage(
        os.path.dirname(path),
        os.path.splitext(os.path.basename(path))[0])
    os.remove(path)
    fp._set_all_reached_functions_runtime()

    assert fp.reaches_func_runtime('abc')
    assert fp.reaches_func_runtime('stu')
    assert fp.reaches_func_runtime('Random')
    assert not fp.reaches_func_runtime('def')
    assert not fp.reaches_func_runtime('jkl')

    # Runtime or tatically reached functions
    assert fp.reaches_func_combined('abc')
    assert fp.reaches_func_combined('stu')
    assert fp.reaches_func_combined('Random')
    assert fp.reaches_func_combined('def')
    assert not fp.reaches_func_combined('jkl')
