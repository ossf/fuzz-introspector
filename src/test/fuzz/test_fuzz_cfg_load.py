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
"""Fuzz cfg_load.py"""

import os
import sys
import atheris
import pytest

sys.path.append(os.path.dirname(os.path.realpath(__file__)) + "/../../")

from fuzz_introspector import cfg_load  # noqa: E402
from fuzz_introspector import exceptions  # noqa: E402


@pytest.mark.parametrize(
    "data",
    [
        b"random_data",
        b"more random data"
    ]
)
@atheris.instrument_func
def test_TestOneInput(data):
    """Fuzz cfg_load.data_file_read_calltree"""
    cfg_file = "/tmp/test_file.data"
    with open(cfg_file, "wb") as f:
        f.write(data)

    # Read the file as a calltree
    try:
        cfg_load.data_file_read_calltree(cfg_file)
    except exceptions.FuzzIntrospectorError:
        pass

    if os.path.isfile(cfg_file):
        os.remove(cfg_file)


def is_this_a_reproducer_run(argvs):
    """Hack to check if the argvs command shows this is a reproducer run
    This is to bypass https://github.com/google/oss-fuzz/issues/9222 for now
    """
    for arg in argvs:
        if os.path.isfile(arg):
            bname = os.path.basename(arg)

            # Assume a seed file does not have fuzz in its basename
            if "fuzz" not in bname:
                return True
    return False


def main():
    if not is_this_a_reproducer_run(sys.argv):
        atheris.instrument_all()

    atheris.Setup(
        sys.argv,
        test_TestOneInput,
        enable_python_coverage=True
    )
    atheris.Fuzz()


if __name__ == "__main__":
    main()
