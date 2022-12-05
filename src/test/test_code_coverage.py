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

sys.path.append(os.path.dirname(os.path.realpath(__file__)) + "/../")

from fuzz_introspector import code_coverage  # noqa: E402

TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')


def test_load_llvm_coverage():
    """Tests loading llvm coverage from a .covreport file."""
    cov_profile = code_coverage.load_llvm_coverage(TEST_DATA_PATH)
    assert len(cov_profile.covmap) > 0
    assert len(cov_profile.file_map) == 0
    assert len(cov_profile.branch_cov_map) > 0
    assert cov_profile._cov_type == "function"
    assert len(cov_profile.coverage_files) == 1
    assert len(cov_profile.dual_file_map) == 0

    assert cov_profile.covmap['BZ2_bzCompress'][0] == (408, 46800)
    assert cov_profile.covmap['BZ2_bzCompress'][7] == (416, 93600)
    assert cov_profile.covmap['BZ2_bzCompress'][10] == (420, 0)
    assert cov_profile.covmap['add_pair_to_block'][0] == (217, 3600000)
    assert cov_profile.covmap['add_pair_to_block'][4] == (221, 1440000)
    assert cov_profile.covmap['add_pair_to_block'][11] == (228, 3510000)

    assert cov_profile.branch_cov_map['BZ2_bzCompress:411,8'] == [0, 46800]
    assert cov_profile.branch_cov_map['BZ2_bzCompress:414,8'] == [0, 46800]
    assert cov_profile.branch_cov_map['BZ2_bzCompress:417,4'] == [0, 93600, 0, 46800, 0, 46800]
    assert cov_profile.branch_cov_map['BZ2_bzCompress:425,20'] == [0, 0]
    assert cov_profile.branch_cov_map['BZ2_bzCompress:443,14'] == [0, 0]
    assert cov_profile.branch_cov_map['add_pair_to_block:220,16'] == [1440000, 3600000]
    assert cov_profile.branch_cov_map['add_pair_to_block:224,4'] == (
        [32600, 3600000, 32600, 3510000, 1570000])
