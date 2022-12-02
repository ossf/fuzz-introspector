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
"""Test code_coverage.py"""

import os
import sys
import pytest

sys.path.append(os.path.dirname(os.path.realpath(__file__)) + "/../")

from fuzz_introspector import code_coverage  # noqa: E402
from fuzz_introspector.datatypes import function_profile  # noqa: E402


@pytest.fixture
def sample_jvm_coverage_xml():
    """Fixture for a sample jvm_coverage_xml"""
    cfg_str = """<!DOCTYPE report PUBLIC "-//JACOCO//DTD Report 1.1//EN" "report.dtd">
<report name="JaCoCo Coverage Report">
  <sessioninfo id="9253a4a5cb62-c5efb6cd" start="1669995723552" dump="1669995724729"/>
  <package name="">
    <class name="BASE64EncoderStreamFuzzer" sourcefilename="BASE64EncoderStreamFuzzer.java">
      <method name="&lt;init&gt;" desc="()V" line="24">
        <counter type="INSTRUCTION" missed="3" covered="0"/>
        <counter type="LINE" missed="1" covered="0"/>
        <counter type="COMPLEXITY" missed="1" covered="0"/>
        <counter type="METHOD" missed="1" covered="0"/>
      </method>
      <method name="fuzzerTestOneInput" desc="(LFuzzedDataProvider;)V" line="26">
        <counter type="INSTRUCTION" missed="2" covered="16"/>
        <counter type="LINE" missed="2" covered="5"/>
        <counter type="COMPLEXITY" missed="0" covered="1"/>
        <counter type="METHOD" missed="0" covered="1"/>
      </method>
    </class>
    <sourcefile name="BASE64EncoderStreamFuzzer.java">
      <line nr="23" mi="3" ci="0" mb="0" cb="0"/>
      <line nr="25" mi="0" ci="3" mb="0" cb="0"/>
      <line nr="27" mi="0" ci="6" mb="0" cb="0"/>
      <counter type="INSTRUCTION" missed="3" covered="21"/>
      <counter type="LINE" missed="1" covered="6"/>
      <counter type="COMPLEXITY" missed="1" covered="1"/>
      <counter type="METHOD" missed="1" covered="1"/>
      <counter type="CLASS" missed="0" covered="1"/>
    </sourcefile>
  </package>
</report>"""
    return cfg_str


def write_coverage_file(tmpdir, coverage_file):
    # Write the coverage_file
    path = os.path.join(tmpdir, "jacoco.xml")
    with open(path, "w") as f:
        f.write(coverage_file)


def generate_temp_function_profile(name, source):
    elem = dict()
    elem["functionName"] = name
    elem["functionSourceFile"] = source
    elem["functionLinenumber"] = 13
    elem['linkageType'] = None
    elem['returnType'] = None
    elem['argCount'] = None
    elem['argTypes'] = None
    elem['argNames'] = None
    elem['BBCount'] = None
    elem['ICount'] = None
    elem['EdgeCount'] = None
    elem['CyclomaticComplexity'] = None
    elem['functionsReached'] = []
    elem['functionUses'] = None
    elem['functionDepth'] = None
    elem['constantsTouched'] = None
    elem['BranchProfiles'] = []
    elem['Callsites'] = []

    return function_profile.FunctionProfile(elem)


def test_jvm_coverage(tmpdir, sample_jvm_coverage_xml):
    """Basic test for jvm coverage"""
    write_coverage_file(tmpdir, sample_jvm_coverage_xml)

    # Generate Coverage Profile
    cp = code_coverage.load_jvm_coverage(tmpdir)

    # Assure coverage profile has been correctly retrieved
    assert cp is not None

    # Ensure getting the correct coverage file
    assert len(cp.coverage_files) == 1
    assert cp.coverage_files == [os.path.join(tmpdir, "jacoco.xml")]

    # Ensure file map is correct
    assert len(cp.file_map) == 1
    assert "BASE64EncoderStreamFuzzer" in cp.file_map
    assert cp.file_map["BASE64EncoderStreamFuzzer"] == [(25, 1000), (27, 1000)]

    # Ensure dual file map is correct
    assert len(cp.dual_file_map) == 1
    assert "BASE64EncoderStreamFuzzer" in cp.dual_file_map
    assert len(cp.dual_file_map["BASE64EncoderStreamFuzzer"]) == 2
    assert "executed_lines" in cp.dual_file_map["BASE64EncoderStreamFuzzer"]
    assert "missing_lines" in cp.dual_file_map["BASE64EncoderStreamFuzzer"]
    assert len(cp.dual_file_map["BASE64EncoderStreamFuzzer"]["executed_lines"]) == 2
    assert len(cp.dual_file_map["BASE64EncoderStreamFuzzer"]["missing_lines"]) == 1
    assert cp.dual_file_map["BASE64EncoderStreamFuzzer"]["executed_lines"] == [25, 27]
    assert cp.dual_file_map["BASE64EncoderStreamFuzzer"]["missing_lines"] == [23]


def test_jvm_coverage_correlation(tmpdir, sample_jvm_coverage_xml):
    """Test jvm coverage correlation"""
    write_coverage_file(tmpdir, sample_jvm_coverage_xml)

    # Generate Coverage Profile
    cp = code_coverage.load_jvm_coverage(tmpdir)

    # Assure coverage profile has been correctly retrieved
    assert cp is not None

    # Generate test function list
    function_list = dict()
    function_list["<init>"] = generate_temp_function_profile(
        "<init>",
        "BASE64EncoderStreamFuzzer"
    )
    function_list["fuzzerTestOneInput"] = generate_temp_function_profile(
        "fuzzerTestOneInput",
        "BASE64EncoderStreamFuzzer"
    )
    function_list["test"] = generate_temp_function_profile(
        "test",
        "test"
    )

    # Correlate jvm coverage map
    cp.correlate_jvm_method_with_coverage(function_list)

    # Ensure the coverage map result is correct
    assert len(cp.covmap) == 2
    assert "<init>" in cp.covmap
    assert "fuzzerTestOneInput" in cp.covmap
    assert cp.covmap["<init>"] == []
    assert cp.covmap["fuzzerTestOneInput"] == [(25, 1000), (27, 1000), (23, 0)]
