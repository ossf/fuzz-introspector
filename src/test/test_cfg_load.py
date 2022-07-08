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

from fuzz_introspector import cfg_load  # noqa: E402


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


def _load_cfg(tmpd, cfg: str):
    cfg_path = os.path.join(tmpd, "test_file.data")
    with open(cfg_path, "w") as f:
        f.write(cfg)
    return cfg_load.data_file_read_calltree(cfg_path)


def test_load_cfg(tmpdir, sample_cfg1):
    cfg = _load_cfg(tmpdir, sample_cfg1)
    assert cfg is not None


def test_cfg_len(tmpdir, sample_cfg1):
    cfg = _load_cfg(tmpdir, sample_cfg1)
    all_callsites = cfg_load.extract_all_callsites(cfg)

    assert len(all_callsites) == 6


def test_cfg_nodes(tmpdir, sample_cfg1):
    cfg = _load_cfg(tmpdir, sample_cfg1)
    all_callsites = cfg_load.extract_all_callsites(cfg)

    # Check first callsite
    root_cs = all_callsites[0]
    assert root_cs.dst_function_name == "LLVMFuzzerTestOneInput"
    assert root_cs.src_linenumber == -1

    # Check last callsite
    last_cs = all_callsites[-1]
    assert last_cs.dst_function_name == "fuzz"
    assert last_cs.src_linenumber == 74

    # Check depths of all callsites
    assert all_callsites[0].depth == 0
    assert all_callsites[1].depth == 1
    assert all_callsites[2].depth == 2
    assert all_callsites[3].depth == 2
    assert all_callsites[4].depth == 2
    assert all_callsites[5].depth == 2
