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
import json
import argparse

from pycg.pycg import CallGraphGenerator
from pycg import formats
from pycg.utils.constants import CALL_GRAPH_OP

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--fuzzer",
        help="Fuzzer to be processed"
    )
    parser.add_argument(
        "--package",
        help="Package containing the code to be analyzed",
        default=None
    )
    args = parser.parse_args()
    run_fuzz_pass(args.fuzzer, args.package)

def resolve_package(fuzzer_path):
    """Resolves the package of a fuzzer"""
    print("Fuzzer path: %s"%(fuzzer_path))
    dirpath = os.path.dirname(fuzzer_path)

    # sanity check one
    all_dirs = []
    for d in os.listdir(dirpath):
        if os.path.isdir(os.path.join(dirpath, d)):
            all_dirs.append(d)

    # Read all potential imports in the fuzzer
    fuzz_content = ""
    with open(fuzzer_path, "r") as fp:
        fuzz_content = fp.read()

    # Now go through each of the directories and check if any dir is in the fuzzer
    imported_dirs = []
    for d in all_dirs:
        if d in fuzz_content:
            print("Directory: %s"%(d))
            imported_dirs.append(d)

    if len(imported_dirs) > 0:
        print("Package path: %s"%(dirpath))
        return dirpath + "/"

    print("Could not identify the package")
    return None

def run_fuzz_pass(fuzzer, package):
    if package is None:
        package = resolve_package(fuzzer)
        if package is None:
            print("No package. Exiting early now as the results will not be good")
            sys.exit(1)

    print("Fuzzer: %s"%(fuzzer))
    print("Package: %s"%(package))
    cg = CallGraphGenerator(
        [ fuzzer ],
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
    print(json.dumps(cg_extended, indent=4))
    print_calltree(cg_extended['cg'], ep_key, set())

def print_calltree(cg_extended, k, s1, depth=0, lineno=-1, themod="", ext_mod=""):
    """Prints a calltree where k is the key in the cg of the root"""

    if depth > 20:
        return
    print("%s%s src_mod=%s src_linenumber=%d dst_mod=%s"%(" "*(depth*2), k, themod, lineno, ext_mod))
    sorted_keys = sorted(cg_extended[k]['dsts'], key=lambda x: x['lineno'])

    # Avoid deep recursions
    if k in s1:
        return

    s1.add(k)
    for dst in cg_extended[k]['dsts']:
        print_calltree(cg_extended, dst['dst'], s1, depth+1, dst['lineno'], dst['mod'], dst['ext_mod'])

if __name__ == "__main__":
    main()
