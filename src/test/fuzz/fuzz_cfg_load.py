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

sys.path.append(os.path.dirname(os.path.realpath(__file__)) + "/../../")

from fuzz_introspector import cfg_load  # noqa: E402
from fuzz_introspector import exceptions  # noqa: E402


@atheris.instrument_func
def TestOneInput(data):
    """Fuzz cfg_load.data_file_read_calltree"""
    cfg_file = "test_file.data"
    with open(cfg_file, "wb") as f:
        f.write(data)

    # Read the file as a calltree
    try:
        cfg_load.data_file_read_calltree(cfg_file)
    except exceptions.FuzzIntrospectorError:
        pass

    if os.path.isfile(cfg_file):
        os.remove(cfg_file)


def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
