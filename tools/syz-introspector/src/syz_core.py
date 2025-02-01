# Copyright 2025 Fuzz Introspector Authors
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
"""Core syz-introspector module."""

import os
import sys
import json
import logging
from typing import Any, Dict, List, Set

import yaml
from fuzz_introspector import commands

import textual_source_analysis
import fuzz_introspector_utils
import syzkaller_util

logger = logging.getLogger(name=__name__)


def find_ioctl_first_case_uses(ioctl_handler, kernel_folder):
    """Finds the source file of a given ioctl handler function and scans
    for each ioctl identified for the first line index of:
    "case IOCTL_NAME"
    This is a heuristic for identifying where the ioctl is used in
    switch statement."""

    # join the kernel folder and the path identified by fuzz introspector. This
    # is needed because otherwise relative paths may cause issues due to
    # different working directories of the compiler versus the post processing.
    src_file = os.path.join(
        kernel_folder, ioctl_handler['func']['file_location'].split(':')[0])

    src_file = textual_source_analysis.find_file(src_file)
    if not src_file:
        return []

    with open(src_file, 'r', encoding='utf-8') as f:
        content = f.read()

    pair_starts = list()
    for idx, line in enumerate(content.split('\n')):
        already_seen = set()
        for ioctl in ioctl_handler['ioctls']:
            if ioctl.name in line and ioctl.name not in already_seen and 'case' in line:
                logger.debug("%s :: %d", line.replace("\n", ""), idx)
                already_seen.add(ioctl.name)
                pair_starts.append((ioctl.name, idx + 1))
    return pair_starts


def extract_header_files_referenced(workdir, all_sources) -> Set[str]:
    """extract the source of all header files from FI output."""

    raw_header_file_references = fuzz_introspector_utils.get_all_header_files_in_light(
        workdir, all_sources)

    all_files = set()
    for raw_file_reference in raw_header_file_references:
        logger.info('Header file -: %s', raw_file_reference)
        path2 = raw_file_reference.replace('file_location:',
                                           '').strip().split(':')[0].replace(
                                               "'", '')
        normalized = os.path.normpath(path2)
        logger.info('Adding %s', normalized)
        all_files.add(normalized)

    logger.debug('Files found')
    for normalized_path in all_files:
        logger.debug('normalized_path: %s', normalized_path)

    new_files = set()
    for header_file in all_files:
        logger.debug('- %s', header_file)
        if not os.path.isfile(header_file):
            continue
        with open(header_file, 'r', encoding='utf-8') as f:
            try:
                content = f.read()
            except UnicodeDecodeError:
                content = ''
            for line in content.split('\n'):
                if '#include' not in line:
                    continue
                if '.h' not in line:
                    continue
                header_included = line.replace('#include', '').replace(
                    '>', '').replace('<', '').replace('\"',
                                                      '').replace(' ', '')
                #header_included_path = os.path.join(
                #    os.path.dirname(header_file), header_included)

                logger.info('Including: %s', header_included)
                new_files.add(header_included)
    all_files = all_files.union(new_files)

    found_files = []
    for header_file in all_files:
        logger.info('Finding F1')
        valid_target = textual_source_analysis.find_file(header_file)
        if valid_target:
            found_files.append(valid_target)
    for header_file in found_files:
        logger.debug('- %s', header_file)

    return found_files


def extract_syzkaller_types_to_analyze(ioctls, syzkaller_description,
                                       typedict) -> Dict[str, str]:
    """goes through ioctls_per_fp and syzkaller_description, and sets something
    in syzkaller_description and returns a set of types to analyse."""

    all_types_to_print = set()
    for ioctl in ioctls:
        type_to_print = ioctl.type.replace('struct', '').replace('*',
                                                                 '').strip()
        for struct_type in typedict['structs']:
            if struct_type['name'] == type_to_print:
                all_types_to_print.add(type_to_print)

    all_types = set()
    visited = set()
    while all_types_to_print:
        elem = all_types_to_print.pop()
        if elem not in visited:
            all_types.add(elem)
            visited.add(elem)
        for struct_type in typedict['structs']:
            if struct_type['name'] == elem:
                for field in struct_type['fields']:
                    if field['type'] not in all_types:
                        to_add = field['type'].replace('struct',
                                                       '').replace(' ', '')
                        if to_add not in visited:
                            all_types_to_print.add(field['type'].replace(
                                'struct', '').replace(' ', ''))
                            visited.add(to_add)
    logger.info('Found all types to print:')

    description_types = dict()
    for dtype in all_types:
        logger.info('- %s', dtype)

        if dtype in description_types:
            continue

        for struct_type in typedict['structs']:
            if struct_type['name'] == dtype:
                logger.info('Creating syzkaller type for: %s', elem)
                description_str = '# Source code: %s (%d, %d)\n' % (
                    struct_type['source_file'],
                    struct_type['pos']['line_start'],
                    struct_type['pos']['line_end'])
                description_str += '%s {\n' % (dtype)
                for field in struct_type['fields']:
                    logger.debug(' -- field type: %s', field['type'])
                    if field['type'] not in all_types:
                        all_types_to_print.add(field['type'])
                    syz_type = syzkaller_util.convert_raw_type_to_syzkaller_type(
                        field['type'])
                    syz_name = field['name']
                    if syz_name.startswith('*'):
                        target = '%s     arg ptr[inout, %s]' % (
                            syz_name[1:], syz_type.replace(
                                'struct', '').replace(' ', ''))
                    elif '[' in syz_name:
                        array_count = syz_name.split('[')[1].split(']')[0]
                        field_name = syz_name.split('[')[0]
                        arr_type = field['type'].replace('struct',
                                                         '').replace(' ', '')
                        target = '%s  array[%s, %s]' % (field_name, arr_type,
                                                        array_count)
                    else:
                        target = '%s     %s' % (syz_name, syz_type)
                    description_str += ' %s\n' % (target)

                description_str += '}'
                description_types[dtype] = description_str

    return description_types


def get_next_syzkaller_workdir():
    """Get next working directory."""
    idx = 0
    while True:
        filename = f'auto-syzkaller-{idx}'
        if not os.path.isdir(filename):
            return filename
        idx += 1


def write_syzkaller_description(ioctls, syzkaller_description, workdir,
                                all_devnodes, header_file, target_path):
    """Writes a description-X.txt representing syzkaller description."""

    # Ensure there are actually ioctls to generate
    if not ioctls:
        return None

    curr_descr_idx = 0
    next_syz_descr = os.path.join(workdir, f'description-{curr_descr_idx}.txt')
    while os.path.isfile(next_syz_descr):
        curr_descr_idx += 1
        next_syz_descr = os.path.join(workdir,
                                      f'description-{curr_descr_idx}.txt')
    with open(next_syz_descr, 'w', encoding='utf-8') as f:
        # Define the header files to include
        source_files = set()

        for ioctl_content in ioctls:
            source_files.add(ioctl_content.definition_src_file)

        f.write('# Auto-generated syzkaller description by Syz-Introspector\n')
        f.write('#\n')
        f.write(f'# Target: {target_path}\n')
        f.write('#\n\n')
        f.write('include <uapi/linux/fcntl.h>\n')
        for source_file in source_files:
            f.write(f'include <{source_file}>\n')
        f.write('\n' * 2)

        f.write('resource fd_target[fd]\n\n')

        for devnode in all_devnodes:
            f.write(f'openat${devnode}_target(fd const[AT_FDCWD], '
                    f'file ptr[in, string["/dev/{devnode}"]], '
                    'flag flags[open_flags]) fd_target\n')
        f.write('\n' * 2)

        # Describe the ioctls
        # Write ioctls in groups of the files they are defined in
        ioctl_src_files = set()
        for ioctl in ioctls:
            ioctl_src_files.add(ioctl.definition_src_file)

        for src_file in ioctl_src_files:
            f.write(f'# ioctls defined in {src_file}\n')
            for ioctl in ioctls:
                if ioctl.definition_src_file == src_file:
                    ioctl_type = syzkaller_util.get_type_ptr_of_syzkaller(
                        ioctl)
                    f.write(
                        'ioctl$auto_%s(fd fd_target, cmd const [%s], %s)\n' %
                        (ioctl.name, ioctl.name, ioctl_type))
            f.write('\n\n')
        f.write('\n' * 2)

        # Describe the types
        for st, text in syzkaller_description.items():  #['types']:
            f.write(text)
            f.write('\n' * 2)
    return next_syz_descr


def get_function_containing_line_idx(line_idx, sorted_functions):
    """Gets function on the line idx"""
    for idx, func1 in enumerate(sorted_functions):
        if idx + 2 < len(sorted_functions):
            func2 = sorted_functions[idx + 1]
            if (func1['analysis']['source_line'] < line_idx
                    and func2['analysis']['source_line'] > line_idx):
                return func1
    return None


def check_source_files_for_ioctl(kernel_folder, src_file, ioctls,
                                 all_files_with_func):
    """For a given set of of IOCTLs and a source file, finds the functions
    in the source file from the `all_files_with_func` that uses the IOCTLs."""
    all_ioctl_func_handlers = list()

    logger.info('Finding F2')
    target_file = textual_source_analysis.find_file(src_file)
    if not target_file:
        return []
    with open(target_file, 'r', encoding='utf-8') as f:
        content = f.read()

    functions_with_ioctls_in_them = dict()

    # Scan for ioctls
    all_functions = all_files_with_func[src_file]
    sorted_functions = sorted(all_functions,
                              key=lambda a: int(a['analysis']['source_line']))
    lines = content.split("\n")

    for line_idx, line in enumerate(lines):
        # Get the ioctls mentioned on this line
        ioctls_in_line = []
        for ioctl in ioctls:
            if ioctl.name in line:
                logger.info('%s :: found {%s} on line {%s} {line no: %d}',
                            target_file, ioctl.name, line, line_idx)
                ioctls_in_line.append(ioctl)

        # Extract the functions holding the lines
        for ioctl in ioctls_in_line:
            func_with_ioctl = get_function_containing_line_idx(
                line_idx, sorted_functions)
            if not func_with_ioctl:
                continue
            # We found the function with the line index
            if func_with_ioctl[
                    'functionName'] not in functions_with_ioctls_in_them:
                functions_with_ioctls_in_them[
                    func_with_ioctl['functionName']] = {
                        'func': func_with_ioctl,
                        'ioctls': list()
                    }
            functions_with_ioctls_in_them[
                func_with_ioctl['functionName']]['ioctls'].append(ioctl)

    if len(functions_with_ioctls_in_them) > 0:
        logger.debug('Functions with ioctls in them')
        for interesting_func in functions_with_ioctls_in_them:
            all_ioctl_func_handlers.append(
                functions_with_ioctls_in_them[interesting_func])
            logger.debug(
                "- %s",
                functions_with_ioctls_in_them[interesting_func]['func'])
            for ioctl in functions_with_ioctls_in_them[interesting_func][
                    'ioctls']:
                logger.debug('  - %s', (ioctl.name))

    return all_ioctl_func_handlers


def load_all_funcs():
    """Loads the .yaml function file from Fuzz Introspector."""
    all_funcs = None
    for filename in os.listdir(os.getcwd()):
        if (filename.startswith('fuzzerLogFile')
                and filename.endswith('.data.yaml')):
            with open(filename, 'r', encoding='utf-8') as f:
                all_funcs = yaml.safe_load(f)
    if not all_funcs:
        return False

    return all_funcs


def find_all_unlocked_ioctls(source_files_to_functions_mapping):
    """Finds IOCTL handlers in the source code based on unlocked_ioctl
    values found. This is based on finding the right handler in the fops
    struct."""
    unlocked_ioctl_functions = []
    for src_file in source_files_to_functions_mapping:
        target_file = textual_source_analysis.find_file(src_file)
        if not target_file:
            continue
        # logging.info('Reading: %s'%(src_file))
        with open(target_file, 'r', encoding='utf-8') as f:
            content = f.read()
        if ".unlocked_ioctl" in content:
            logger.info('Found unlocked ioctl: %s', target_file)
            ioctl_func = ''
            for line in content.split('\n'):
                line = line.replace('\t', ' ')
                if '.unlocked_ioctl =' in line:
                    logger.info('unlocked line: %s', line)
                    ioctl_func = line.split('=')[-1].replace(' ', '').replace(
                        ',', '')
                    unlocked_ioctl_functions.append(ioctl_func)
    return unlocked_ioctl_functions


def get_ioctl_handlers(ioctls, kernel_folder, report, fi_data_dir):
    """Finds the places in the source code where IOCTL commands are used."""

    logger.info('Handle 1')
    # Look through all of the functions in the output
    all_functions = fuzz_introspector_utils.get_light_functions(fi_data_dir)

    source_files_to_functions_mapping = fuzz_introspector_utils.get_source_to_functions_mapping(
        all_functions)
    logger.info('Handle 2')

    # Get functions assigned in a statement of .unlocked_ioctl = ...
    unlocked_ioctls = find_all_unlocked_ioctls(
        source_files_to_functions_mapping)
    unlocked_ioctl_handlers = []
    for unlocked_ioctl in unlocked_ioctls:
        logger.info('Checking unlocked: %s', unlocked_ioctl)
        for func in all_functions:
            if unlocked_ioctl == func['functionName']:
                logger.info('Found function')
                logger.info(json.dumps(func, indent=2))
                unlocked_ioctl_handlers.append({'func': func, 'ioctls': []})

    logger.info('Handle 3')
    # In case no unlocked_ioctl assignments are found, search for source files
    # that reference that use of the IOCTLs.
    ioctl_handlers = []
    if not unlocked_ioctl_handlers:
        logger.info(
            'Found no unlocked ioctl handlers. Trying to search for ioctls.')

        for src_file in source_files_to_functions_mapping:
            tmp_ioctl_handlers = check_source_files_for_ioctl(
                kernel_folder, src_file, ioctls,
                source_files_to_functions_mapping)
            ioctl_handlers += tmp_ioctl_handlers

    logger.info('Handle 4')
    for unlocked_ioctl_handler in unlocked_ioctl_handlers:
        ioctl_handlers.append(unlocked_ioctl_handler)

    logger.info('Handle 5')
    # Find the module names
    for ioctl_handler in ioctl_handlers:
        logger.info('Finding devnodes for %s',
                    ioctl_handler['func']['analysis']['source_file'])
        possible_dev_names = textual_source_analysis.get_possible_devnames(
            ioctl_handler['func']['analysis']['source_file'], kernel_folder)
        ioctl_handler['possible-dev-names'] = possible_dev_names
    logger.info('Handle 6')

    return ioctl_handlers


def interpret_complexity_of_ioctl_handlers(ioctl_handlers):
    """Dump complexity of ioctl handlers."""

    all_funcs = load_all_funcs()
    if all_funcs:
        for ioctl_handler in ioctl_handlers:
            for fi_func in all_funcs['All functions']['Elements']:
                if fi_func['functionName'] == ioctl_handler['func']['name']:
                    ioctl_handler['introspector-func'] = fi_func


def parse_existing_description(existing_description: str):
    """Reads the ioctls of existing description"""
    if not os.path.isfile(existing_description):
        logger.info('Provided description does not exist. Aborting')
        sys.exit(0)

    with open(existing_description, 'r', encoding='utf-8') as f:
        contents = f.read()
    ioctl_cmds = []
    for line in contents.split('\n'):
        if line.startswith('ioctl') and '$' in line:

            # Get the ioctl cmd
            args = '('.join(line.split('(')[1:])
            second_arg = args.split(',')[1]
            ioctl_cmd = second_arg.split('[')[-1].replace(']', '')
            ioctl_type_arg = ','.join(args.split(',')[2:]).strip()
            ioctl_cmds.append({'name': ioctl_cmd, 'type': ioctl_type_arg})
    return ioctl_cmds


def diff_analysis_to_existing_ioctl(existing_ioctl_commands, all_ioctls):
    """Diff two syzkaller descriptions."""
    logger.info('[+] Existing ioctls:')
    for ioctl in existing_ioctl_commands:
        logger.info(ioctl['name'])

    logger.info('[+] Ioctls from analysis:')
    for ioctl in all_ioctls:
        logger.info(json.dumps(ioctl, indent=2))

    logger.info('[+] Checking diff:')
    all_ioctls_in_description = [io['name'] for io in existing_ioctl_commands]
    all_ioctls_from_analysis = [io['name'] for io in all_ioctls]

    logger.info('[+] Diffing ioctls')
    if list(sorted(all_ioctls_in_description)) == list(
            sorted(all_ioctls_from_analysis)):
        logger.info('All ioctls are the same between description and analysis')
    else:
        logger.info('Found a discrepancy')
        for description_ioctl in all_ioctls_in_description:
            if description_ioctl not in all_ioctls_from_analysis:
                logger.info(
                    'Missing from analysis but found in description: %s',
                    description_ioctl)
        for analysis_ioctl in all_ioctls_from_analysis:
            if analysis_ioctl not in all_ioctls_in_description:
                logger.info(
                    'Missing from description but found in analysis: %s',
                    analysis_ioctl)


def dump_report(workdir, report, args):
    """Writes the generate report as a .txt file"""
    logger.info('[+] Workdir with results: %s', workdir)
    report_json_path = os.path.join(workdir, 'report.json')
    ioctl_list = []
    for ioctl in report['ioctls']:
        ioctl_list.append(ioctl.to_dict())
    report_to_dump = {
        'ioctls': ioctl_list,
        'c-files': report['c_files'],
        'loc': report['loc'],
    }
    with open(report_json_path, 'w', encoding='utf-8') as f:
        f.write(json.dumps(report_to_dump))

    report_path = os.path.join(workdir, 'report.txt')
    logger.info('[+] - report: %s', report_path)
    with open(report_path, 'w', encoding='utf-8') as f:
        # Log summary of files used
        f.write('Kernel driver analysis\n')
        f.write(f'Target: \n- {args.target}\n')

        # Describe information on the IOCTLs
        f.write('\nIOCTL analysis:\n')
        f.write('- Found a total of %d ioctls' % (len(report['ioctls'])))
        for ioctl in report['ioctls']:
            f.write('-- Ioctl:')
            f.write('%s :: %s :: %s' %
                    (ioctl.name, ioctl.type, ioctl.direction))

        f.write(
            '\nThe above IOCTLs are defined in the following header files:\n')
        for ioctl in report['ioctls']:
            f.write(f'- {ioctl.definition_src_file}')

        # IOCTL handlers
        f.write('\n\nThe IOCTL handlers for these ioctls:\n')
        # f.write(json.dumps(report['ioctl_handlers'],indent=2))
        for ioctl_handler in report['ioctl_handlers']:
            f.write('- %s' % (ioctl_handler['func']['functionName']))

        f.write('\n\n# Details on these IOCTL handlers:\n')

        for ioctl_handler in report['ioctl_handlers']:
            f.write('>' * 40 + '\n')
            f.write(
                json.dumps(ioctl_handler.get('introspector-func', {}),
                           indent=2))
            f.write('\n')
            f.write('ioctls:\n')
            for ioctl in ioctl_handler.get('ioctls', []):
                f.write(f'{str(ioctl)}\n')

        f.write('\n\n# Calltrees of these IOCTL handlers:\n')
        for ioctl_handler in report['ioctl_handlers']:
            f.write(ioctl_handler['calltree'])


def highlight_ioctl_entrypoints_in_calltree(ioctl_handler, kernel_folder,
                                            calltree):
    """For a given IOCTL handler and its calltree this function highlights
    where in the calltree the IOCTLs are in the calltree."""
    pair_starts = find_ioctl_first_case_uses(ioctl_handler, kernel_folder)

    ioctl_handler_start = int(
        ioctl_handler['func']['file_location'].split(':')[-1])
    idxs = []
    for line in calltree.split('\n'):
        # Skip lines for callsites with depth higher than 1.
        if line.startswith('   '):
            continue
        if 'linenumber' not in line:
            continue
        curr_idx = int(line.split('linenumber=')[-1])
        logger.info('- %d', curr_idx)
        if curr_idx < ioctl_handler_start:
            continue
        idxs.append(curr_idx)

    starting_points = []
    for idx_to_count, curr_idx in enumerate(idxs):
        try:
            next_idx = idxs[idx_to_count + 1]
        except Exception:
            continue
        for ioctl_name, ioctl_idx in pair_starts:
            if ioctl_idx > curr_idx and ioctl_idx < next_idx:
                logger.info('Found starting point of: %s : %d', ioctl_name,
                            next_idx)
                starting_points.append((ioctl_name, next_idx))

    new_calltree = ''
    for line in calltree.split('\n'):
        if line.startswith('   '):
            new_calltree += line + '\n'
            continue

        if 'linenumber' not in line:
            new_calltree += line + '\n'
            continue
        curr_idx = int(line.split('linenumber=')[-1])
        for ioctl_name, idx_to_start in starting_points:
            if idx_to_start == curr_idx:
                new_calltree += f'IOCTL command start: {ioctl_name}\n'
        new_calltree += line + '\n'
    return new_calltree


def get_next_handler_workdir_idx(workdir: str) -> int:
    """Gets next handler work directory index"""
    handler_idx = 0
    raw_fi_data = os.path.join(workdir, f'handler-analysis-{handler_idx}')
    while os.path.isdir(raw_fi_data):
        handler_idx += 1
        raw_fi_data = os.path.join(workdir, f'handler-analysis-{handler_idx}')

    return handler_idx


def create_fuzz_introspector_html_report(workdir, target, entry_point_func,
                                         html_idx) -> None:
    """Runs HTML report generation based of FI frontend data."""
    # Create Fuzz Introspector HTML report
    fi_html_dir = os.path.join(workdir, f'handler-analysis-{html_idx}',
                               'html-report')
    os.mkdir(fi_html_dir)

    raw_fi_data = os.path.join(workdir, f'handler-analysis-{html_idx}',
                               'fi-data')

    analyses_to_run = [
        "OptimalTargets", "RuntimeCoverageAnalysis", "FuzzEngineInputAnalysis",
        "FilePathAnalyser", "MetadataAnalysis", "AnnotatedCFG"
    ]
    curr_wd = os.getcwd()
    os.chdir(fi_html_dir)
    os.environ['FI_ENTRYPOINT'] = entry_point_func
    commands.run_analysis_on_dir(
        target_folder=raw_fi_data,
        coverage_url='',
        analyses_to_run=analyses_to_run,
        correlation_file='',
        enable_all_analyses=False,
        report_name=target,
        language='c-cpp',
    )
    os.chdir(curr_wd)


def extract_types_of_syzkaller_description(ioctls, fi_data_dir):
    """Extracts the types needed for a syzkaller description. This means for
    each IOCTL in the IOCTLs in the ioctls_per_fp extracting the names of the
    types of the IOCTL, and then extracting the specific types of these names.
    """

    # Extract type information.
    logger.info('[+] Extracting type information for each ioctl: %s',
                fi_data_dir)

    with open(os.path.join(fi_data_dir, 'report.yaml'), 'r',
              encoding='utf-8') as f:
        report_dict = yaml.safe_load(f)

    type_dict = {'structs': [], 'typedefs': []}
    for source in report_dict.get('sources', []):
        struct_list = source['types']['structs']
        typedefs = source['types']['typedefs']

        for elem in struct_list:
            elem['source_file'] = source['source_file']
        for elem in typedefs:
            elem['source_file'] = source['source_file']

        type_dict['structs'] += struct_list
        type_dict['typedefs'] += typedefs

    syzkaller_description = {'types': dict()}
    all_types_to_decipher = extract_syzkaller_types_to_analyze(
        ioctls, syzkaller_description, type_dict)

    logger.info('All types extracted from struct to include in description:')
    logger.info(json.dumps(list(all_types_to_decipher), indent=2))

    return all_types_to_decipher


def create_and_dump_syzkaller_description(ioctls_per_fp, workdir: str,
                                          all_devnodes, fi_data_dir,
                                          target_path) -> None:
    """Creates a syzkaller description based on the IOCTLs of ioctls_per_fp
    and extracting type information dumped by Fuzz Introspector. Then writes
    this to a file in workdir/description.txt."""

    logger.info('Creating and dumping syzkaller descriptions')
    handled_headers = set()
    header_files_to_ioctls: Dict[str, List[Any]] = {}
    for ioctl in ioctls_per_fp:
        definition_list = header_files_to_ioctls.get(ioctl.definition_src_file,
                                                     [])
        definition_list.append(ioctl)
        header_files_to_ioctls[ioctl.definition_src_file] = definition_list

    syzkaller_description_types = {}
    all_ioctls = []
    for header_file, ioctls in header_files_to_ioctls.items():
        logger.info('Header file:')
        logger.info(header_file)
        all_ioctls.extend(ioctls)

        types_to_dump = extract_types_of_syzkaller_description(
            ioctls, fi_data_dir)
        for type_to_dump, type_text in types_to_dump.items():
            syzkaller_description_types[type_to_dump] = type_text

    # Write the syzkaller description.
    logger.info('[+] Generating a syzkaller description')
    logger.info('[+] Creating syzkaller description for ')

    syzkaller_description_path = write_syzkaller_description(
        all_ioctls, syzkaller_description_types, workdir, all_devnodes, '',
        target_path)
    if syzkaller_description_path:
        logger.info('[+] - auto-generated description: %s',
                    syzkaller_description_path)
    else:
        logger.info('[+] - auto-generated description: None')
