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
    print("Done running pass")

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
    print("Analysing1")
    cg.analyze()
    print("Analysing2")

    formatter = formats.Fuzz(cg)
    cg_extended = formatter.generate()

    calltree, max_depth = convert_to_fuzzing_cfg(cg_extended)
    if calltree == None:
        print("Could not convert calltree to string. Exiting")
        sys.exit(1)

    # Do analysis on the data
    converge_reachables(cg_extended)
    find_all_uses(cg_extended)

    translated_cg = translate_cg(cg_extended, fuzzer)

    fuzzer_name = os.path.basename(fuzzer).replace(".py", "")
    dump_fuzz_logic(fuzzer_name, translated_cg, calltree)

def find_all_uses(cg_extended):
    """Sets functionUses"""
    for elem in cg_extended['cg']:
        all_uses = []
        for elem2 in cg_extended['cg']:
            if elem == elem2:
                continue
            if elem in cg_extended['cg'][elem2]['all_reachables']:
                all_uses.append(elem2)
        cg_extended['cg'][elem]['all_uses'] = len(all_uses)

def extract_local_reachables(elem):
    print(elem)
    s = set()
    for dst in elem['dsts']:
        s.add(dst['dst'])
    return s

def converge_reachables(cg_extended):
    """For each of the elements in the cg_extended cg we converge their reachables"""
    for elem in cg_extended['cg']:
        print(f"Converging {elem}")
        # 'dsts': [{'dst': '<builtin>.type'
        all_reachables = set()
        ws = extract_local_reachables(cg_extended['cg'][elem])
        while len(ws) > 0:
            e1 = ws.pop()
            if e1 not in all_reachables:
                all_reachables.add(e1)
                ws = ws.union(extract_local_reachables(cg_extended['cg'][e1]))
        #print(elem)
        cg_extended['cg'][elem]['all_reachables'] = list(all_reachables)

def translate_cg(cg_extended, fuzzer_filename):
    """Converts the PyCG data into fuzz-introspector data"""
    new_dict = dict()
    new_dict['Fuzzer filename'] = fuzzer_filename
    new_dict['All functions'] = dict()
    new_dict['All functions']['Function list name'] = "All functions"
    new_dict['All functions']['Elements'] = []

    # TODO: do the implementation necessary to carry these out.
    for elem in cg_extended['cg']:
        elem_dict = cg_extended['cg'][elem]
        tmpval, max_depth = get_calltree_as_str(cg_extended['cg'], elem, set())

        d = dict()
        d['functionName'] = elem
        d['functionSourceFile'] = elem_dict['meta']['modname']
        d['linkageType'] = "pythonLinkage"
        if 'lineno' in elem_dict['meta']:
          d['functionLinenumber'] = elem_dict['meta']['lineno']
        else:
          d['functionLinenumber'] = -1
        d['functionDepth'] = max_depth
        d['returnType'] = "N/A"
        d['argCount'] = elem_dict['meta']['argCount'] if 'argCount' in elem_dict['meta'] else 0
        d['constantsTouched'] = []
        d['argNames'] = elem_dict['meta']['argNames'] if 'argNames' in elem_dict['meta'] else []
        d['argTypes'] = elem_dict['meta']['argTypes'] if 'argTypes' in elem_dict['meta'] else []
        d['ICount'] = elem_dict['meta']['exprCount'] if 'exprCount' in elem_dict['meta'] else 0
        d['IfCount'] = elem_dict['meta']['ifCount'] if 'ifCount' in elem_dict['meta'] else 0
        d['functionsReached'] = elem_dict['all_reachables']
        d['functionUses'] = elem_dict['all_uses']
        d['BranchProfiles'] = []

        # Set the following based on ifCount. This should be refined to be more accurrate.
        d['BBCount'] = d['IfCount']
        d['EdgeCount'] = int((d['IfCount']+1) * 1.4)
        d['CyclomaticComplexity'] = d['EdgeCount'] - d['BBCount'] + 2
        new_dict['All functions']['Elements'].append(d)
    return new_dict


def dump_fuzz_logic(fuzzer_name, cg_extended, calltree):
    import yaml
    calltree_file = fuzzer_name + ".data"
    fuzzer_func_data = fuzzer_name + ".data.yaml"

    with open(calltree_file, "w+") as cf:
        cf.write(calltree)

    with open(fuzzer_func_data, "w+") as ffdf:
        ffdf.write(yaml.dump(cg_extended))


def convert_to_fuzzing_cfg(cg_extended):
    """Utility to translate the CG to something fuzz-introspector post-processing
    can use"""
    print("Printing CFG output")
    if "ep" not in cg_extended:
        print("No entrypoints found")
        return None

    # Extract fuzzer entrypoint and print calltree.
    ep_key = cg_extended['ep']['mod'] + "." + cg_extended['ep']['name']    
    ep_node = cg_extended['cg'][ep_key]
    #print(json.dumps(cg_extended, indent=4))
    calltree = "Call tree\n"
    calltree2, max_depth = get_calltree_as_str(cg_extended['cg'], ep_key, set())
    calltree = calltree + calltree2
    #print(calltree)
    return calltree, max_depth

def get_calltree_as_str(cg_extended, k, s1, depth=0, lineno=-1, themod="", ext_mod=""):
    """Prints a calltree where k is the key in the cg of the root"""

    #strline = "%s%s src_mod=%s src_linenumber=%d dst_mod=%s\n"%(" "*(depth*2), k, themod, lineno, ext_mod)
    if themod == "":
        themod="/"
    strline = "%s%s %s %d\n"%(" "*(depth*2), k, themod, lineno)
    #strline = "%s%s src_mod=%s src_linenumber=%d dst_mod=%s\n"%(" "*(depth*2), k, themod, lineno, ext_mod)
    #print("%s%s src_mod=%s src_linenumber=%d dst_mod=%s"%(" "*(depth*2), k, themod, lineno, ext_mod))
    sorted_keys = sorted(cg_extended[k]['dsts'], key=lambda x: x['lineno'])

    # Avoid deep recursions
    if k in s1:
        return strline, depth

    s1.add(k)
    next_depth = depth
    for dst in cg_extended[k]['dsts']:
        tmps, m_depth = get_calltree_as_str(cg_extended, dst['dst'], s1, depth+1, dst['lineno'], dst['mod'], dst['ext_mod'])
        next_depth = max(m_depth, next_depth)
        strline += tmps

    return strline, next_depth
if __name__ == "__main__":
    main()
