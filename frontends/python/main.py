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
import argparse

from pycg.pycg import CallGraphGenerator
from pycg import formats
from pycg.utils.constants import CALL_GRAPH_OP

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "entry_point",
        nargs="*",
        help="Entry points to be processed"
    )
    parser.add_argument(
        "--package",
        help="Package containing the code to be analyzed",
        default=None
    )
    args = parser.parse_args()
    run_fuzz_pass(args.package, args.entry_point)

def run_fuzz_pass(package, entry_point):
    cg = CallGraphGenerator(
        entry_point,
        package,
        -1,
        CALL_GRAPH_OP
    )
    cg.analyze()

    formatter = formats.Fuzz(cg)
    output = formatter.generate()

    convert_to_fuzzing_cfg(output)

def convert_to_fuzzing_cfg(cg_extended):
    """Utility to translate the CG to something fuzz-introspector post-processing
    can use"""
    print("Printing CFG output")
    if "ep" not in cg_extended:
        print("No entrypoints found")
        return

    # Extract fuzzer entrypoint and print calltree.
    ep_key = cg_extended['ep']['mod'] + "." + cg_extended['ep']['name']    
    ep_node = cg_extended['cg'][ep_key]
    print_calltree(cg_extended['cg'], ep_key, set())

def print_calltree(cg_extended, k, s1, depth=0):
    """Prints a calltree where k is the key in the cg of the root"""

    print("%s%s"%(" "*(depth*2), k))
    sorted_keys = sorted(cg_extended[k], key=lambda x: x['lineno'])
    for dst in cg_extended[k]:
        print_calltree(cg_extended, dst['dst'], s1, depth+1)

if __name__ == "__main__":
    main()
