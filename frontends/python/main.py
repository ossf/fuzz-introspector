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
import logging
import argparse

from typing import List

from pycg.pycg import CallGraphGenerator
from pycg import formats
from pycg.utils.constants import CALL_GRAPH_OP

logger = logging.getLogger(name=__name__)


def resolve_package(fuzzer_path):
    """Resolves the package of a fuzzer"""
    print(f"Fuzzer path: {fuzzer_path}")
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
            print(f"Directory: {d}")
            imported_dirs.append(d)

    if len(imported_dirs) > 0:
        print(f"Package path: {dirpath}")
        return dirpath + "/"

    print("Could not identify the package")
    return None


def should_debug() -> bool:
    return "PYINTROSPECTOR_DEBUG" in os.environ


def run_fuzz_pass(
    fuzzer: str,
    package: str,
    sources: List[str],
    scan: bool
) -> int:
    """Runs entire fuzz pass"""
    if package is None:
        package = resolve_package(fuzzer)
        if package is None:
            logger.error("No package. Exiting early now as the results will not be good")
            package = ""

    # If indicated, scan package directory recursively to identify .py files.
    scanned_sources = []
    if scan:
        for root, dirs, files in os.walk(package):
            # avoid test directories. We're not interested in exploring this code.
            to_include = True
            for rdir in os.path.split(root):
                if rdir == "test" or rdir == "tests":
                    to_include = False
            # Avoid any paths with tests or test as a folder
            for split_dir in root.split("/"):
                if split_dir == "tests" or split_dir == "test":
                    to_include = False
            if not to_include:
                continue
            for filename in files:
                logger.debug("Iterating %s ---- %s" % (root, filename))
                fpath = os.path.join(root, filename)
                if not fpath.endswith(".py"):
                    continue
                if filename == os.path.basename(fuzzer):
                    continue
                abs_filepath = os.path.abspath(os.path.join(root, filename))
                scanned_sources.append(abs_filepath)

    logger.info(
        f"Running analysis with arguments: {{fuzzer: {fuzzer}, package: {package} }}"
    )
    sources_to_analyze = [fuzzer] + sources + scanned_sources
    logger.info("Sources to analyze:")
    for srz in sources_to_analyze:
        logger.info("- %s" % (srz))
    cg = CallGraphGenerator(
        [fuzzer] + sources + scanned_sources,
        package,
        1000,
        CALL_GRAPH_OP
    )
    cg.analyze()
    formatter = formats.Fuzz(cg)
    cg_extended = formatter.generate()

    # Extract the class list
    classes = formatter.cg_generator.class_manager.get_classes()
    class_list = []
    for cls in classes:
        class_list.append(cls)

    # Extract information about inheritance in classes.
    inheritance = formatter.cg_generator.class_manager.inheritance
    inh_dict = dict()
    for inh_class in inheritance:
        inh_dict[inh_class] = list(inheritance[inh_class])

    if should_debug():
        logger.info("Printing extended cg")
        print(json.dumps(cg_extended, sort_keys=False, indent=4))
        logger.info("Done printing cg")

    # Post analysis
    res = post_analysis(cg_extended, fuzzer)
    if res is None:
        logger.error("Could not convert calltree to string.")
        return 1

    fuzzer_name, translated_cg, calltree = res

    # Dump the data we collected
    translated_cg['All classes'] = class_list
    translated_cg['Inheritance'] = inh_dict
    dump_fuzz_logic(fuzzer_name, translated_cg, calltree)
    return 0


def post_analysis(cg_extended, fuzzer):
    """Converts an extended callgraph into data fuzz-introspector
    post-processing can use.
    """
    calltree, max_depth = convert_to_fuzzing_cfg(cg_extended)
    if calltree is None:
        print("Could not convert calltree to string. Exiting")
        return None

    # Compute fields in the extended callgraph
    set_all_reachables(cg_extended)
    set_all_uses(cg_extended)

    # Convert extended callgraph to data fuzz-introspector
    # post-processing understands.
    translated_cg = convert_cg_to_introspector_data(cg_extended, fuzzer)

    # Simple way to create a fuzzer name for now. This way of
    # doing it means we can't have multiple fuzzers in the same
    # file (at least they will have same name).
    fuzzer_name = os.path.basename(fuzzer).replace(".py", "")

    return fuzzer_name, translated_cg, calltree


def set_all_uses(cg_extended) -> None:
    """For each element in the extended CG, set the functionUses"""
    for elem in cg_extended['cg']:
        all_uses = []
        for elem2 in cg_extended['cg']:
            if elem == elem2:
                continue
            if elem in cg_extended['cg'][elem2]['all_reachables']:
                all_uses.append(elem2)
        cg_extended['cg'][elem]['all_uses'] = len(all_uses)


def set_all_reachables(cg_extended):
    """For each of the elements in the cg_extended cg we converge their reachables.
    The result of this is that the 'all_reachables' key in the elems dictionary
    will be a set with the all reachable elements by the given element
    """
    for elem in cg_extended['cg']:
        logger.info(f"Converging {elem}")
        all_reachables = set()
        ws = {dst['dst'] for dst in cg_extended['cg'][elem]['dsts']}
        while len(ws) > 0:
            e1 = ws.pop()
            if e1 not in all_reachables:
                all_reachables.add(e1)
                ws = ws.union(
                    {dst['dst'] for dst in cg_extended['cg'][e1]['dsts']}
                )
        cg_extended['cg'][elem]['all_reachables'] = list(all_reachables)


def convert_cg_to_introspector_data(cg_extended, fuzzer_filename):
    """Converts the PyCG data into fuzz-introspector data"""
    new_dict = dict()
    new_dict['Fuzzer filename'] = fuzzer_filename
    new_dict['All functions'] = dict()
    new_dict['All functions']['Function list name'] = "All functions"
    new_dict['All functions']['Elements'] = []
    new_dict['Function coverage'] = dict()
    for elem in cg_extended['function_lines']:
        new_dict['Function coverage'][elem] = list(cg_extended['function_lines'][elem])

    if "ep" in cg_extended:
        new_dict['ep'] = dict()
        new_dict['ep']['func_name'] = cg_extended['ep']['name']
        new_dict['ep']['module'] = cg_extended['ep']['mod']

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
        # Write it out to make lines shorter
        if 'argDefaultValues' in elem_dict['meta']:
            d['argDefaultValues'] = elem_dict['meta']['argDefaultValues']
        else:
            d['argDefaultValues'] = []
        d['ICount'] = elem_dict['meta']['exprCount'] if 'exprCount' in elem_dict['meta'] else 0
        d['IfCount'] = elem_dict['meta']['ifCount'] if 'ifCount' in elem_dict['meta'] else 0
        d['raised'] = list(elem_dict['meta']['raises']) if 'raises' in elem_dict['meta'] else []
        d['functionsReached'] = elem_dict['all_reachables']
        d['functionUses'] = elem_dict['all_uses']
        d['BranchProfiles'] = []
        d['Callsites'] = []

        # Set the following based on ifCount. This should be refined to be more accurrate.
        d['BBCount'] = d['IfCount']
        d['EdgeCount'] = int((d['IfCount'] + 1) * 1.4)
        d['CyclomaticComplexity'] = d['EdgeCount'] - d['BBCount'] + 2
        new_dict['All functions']['Elements'].append(d)
    return new_dict


def dump_fuzz_logic(fuzzer_name, cg_extended, calltree):
    import yaml

    # Prefix for post-processing
    prefix = "fuzzerLogFile-"
    calltree_file = prefix + fuzzer_name + ".data"
    fuzzer_func_data = prefix + fuzzer_name + ".data.yaml"

    # Writes the calltree file
    with open(calltree_file, "w+") as cf:
        cf.write(calltree)

    # Writes the yaml file containing information about all functions etc.
    with open(fuzzer_func_data, "w+") as ffdf:
        ffdf.write(yaml.dump(cg_extended))


def convert_to_fuzzing_cfg(cg_extended):
    """Translate a CG to something fuzz-introspector
    post-processing can use.
    """
    if "ep" not in cg_extended:
        logger.error(
            "No entrypoints in the CG. This can not be made into fuzzer callgraph"
        )
        return None

    # Extract fuzzer entrypoint
    ep_key = cg_extended['ep']['mod'] + "." + cg_extended['ep']['name']

    # Get calltree as string
    calltree, max_depth = get_calltree_as_str(
        cg_extended['cg'],
        ep_key,
        set()
    )
    # prefix calltree
    calltree = "Call tree\n" + calltree
    return calltree, max_depth


def get_calltree_as_str(
    cg_extended,
    key,
    visited,
    depth=0,
    lineno=-1,
    key_mod=""
):
    """Coverts a calltree into a string.

    key is the root from this will convert to a string. First, the
    function converts the values related to k into a string, and
    then iterates through k's children and to perform the same operation.

    This is a recursive function and each key will only be handled once.
    """

    if key_mod == "":
        key_mod = "/"
    strline = "%s%s %s %d\n" % (" " * (depth * 2), key, key_mod, lineno)
    sorted_keys = sorted(cg_extended[key]['dsts'], key=lambda x: x['lineno'])

    # Avoid deep recursions
    if key in visited:
        return strline, depth

    visited.add(key)
    next_depth = depth
    for dst in sorted_keys:
        tmps, m_depth = get_calltree_as_str(
            cg_extended,
            dst['dst'],
            visited,
            depth=depth + 1,
            lineno=dst['lineno'],
            key_mod=dst['mod']
        )
        next_depth = max(m_depth, next_depth)
        strline += tmps

    return strline, next_depth


def get_cmdline_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--fuzzer",
        help="Fuzzer to be processed"
    )
    parser.add_argument(
        "--package",
        help="Package containing the code to be analyzed",
        default="/src/pyintro-pack-deps/",
    )
    parser.add_argument(
        "--sources",
        help="Extra help for identifying sources",
        default=[],
        nargs="+"
    )
    parser.add_argument(
        "--no-scan",
        default=False,
        help="Set if package should not be scanned for sources",
        action="store_true"
    )
    return parser


def main() -> int:
    logging.basicConfig(level=logging.INFO)
    logger.info("Starting analysis")
    parser = get_cmdline_parser()

    args = parser.parse_args()
    scan_package_for_sources = not args.no_scan
    exit_code = run_fuzz_pass(
        args.fuzzer,
        args.package,
        args.sources,
        scan_package_for_sources
    )
    logger.info(f"Done running pass. Exit code: {exit_code}")

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
