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
"""Fuzz report generation routines"""

import os
import sys
import shutil
import atheris
import pytest

sys.path.append(os.path.dirname(os.path.realpath(__file__)) + "/../../")

from fuzz_introspector import commands, exceptions  # noqa: E402

lang_list = ["c-cpp", "python", "jvm"]


@pytest.mark.parametrize(
    "data",
    [
        b"random_data",
        b"more random data"
    ]
)
def test_TestOneInput(data: bytes):
    fdp = atheris.FuzzedDataProvider(data)

    report_dir = "tmpreport"
    if not os.path.isdir(report_dir):
        os.mkdir(report_dir)

    correlation_file = os.path.join(report_dir, "correlation_file.txt")
    with open(correlation_file, "wb") as f:
        f.write(fdp.ConsumeBytes(fdp.ConsumeIntInRange(1, 500)))

    # Create a single fuzz report
    report_cfg_file = os.path.join(report_dir, "fuzzerLogFile-123.data")
    report_yaml_file = os.path.join(report_dir, "fuzzerLogFile-123.data.yaml")

    with open(report_cfg_file, "wb") as f:
        f.write(fdp.ConsumeBytes(fdp.ConsumeIntInRange(1, 5000)))

    with open(report_yaml_file, "wb") as f:
        f.write(fdp.ConsumeBytes(fdp.ConsumeIntInRange(1, 50000)))

    lang_choice = fdp.ConsumeIntInRange(0, len(lang_list) - 1)

    analyses_to_run = []

    try:
        commands.run_analysis_on_dir(
            target_folder=report_dir,
            coverage_url="random_coverage_url",
            analyses_to_run=analyses_to_run,
            correlation_file=correlation_file,
            enable_all_analyses=False,
            report_name="report name",
            language=lang_list[lang_choice],
            output_json=[],
            parallelise=False
        )
    except exceptions.FuzzIntrospectorError:
        pass

    shutil.rmtree(report_dir)


def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, test_TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
