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
"""Fuzz cov_load.py"""

import os
import sys
import atheris
import pytest

sys.path.append(os.path.dirname(os.path.realpath(__file__)) + "/../../")

from fuzz_introspector import code_coverage  # noqa: E402
from fuzz_introspector import exceptions  # noqa: E402


@pytest.mark.parametrize(
    "data",
    [
        b"random_data",
        b"more random data"
    ]
)
def test_TestOneInput(data):
    """Fuzz coverage loading functions.

    The rational behind this is that the coverage files may be broken, and
    we should be resilient against that."""
    cov_file = "jacoco.xml"
    with open(cov_file, "wb") as f:
        f.write(data)

    # Read the file as a calltree
    try:
        code_coverage.load_jvm_coverage(os.getcwd())
    except exceptions.FuzzIntrospectorError:
        pass

    if os.path.isfile(cov_file):
        os.remove(cov_file)


def main():
    atheris.instrument_all()
    atheris.Setup(
        sys.argv,
        test_TestOneInput,
        enable_python_coverage=True
    )
    atheris.Fuzz()


if __name__ == "__main__":
    main()
