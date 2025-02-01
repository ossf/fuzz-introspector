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
"""CLI entrypoint for syz-introspector."""

import os
import logging
import argparse
import shutil
import subprocess
from typing import Any, Dict, List

from fuzz_introspector.frontends import oss_fuzz

import syz_core
import textual_source_analysis
import fuzz_introspector_utils

logger = logging.getLogger(name=__name__)
LOG_FMT = ('%(asctime)s.%(msecs)03d %(levelname)s '
           '%(module)s - %(funcName)s: %(message)s')


def create_workdir() -> str:
    """Creates the next available auto-syzkaller-XXX dir."""
    idx = 0
    while os.path.isdir("auto-syzkaller-%d" % (idx)):
        idx += 1
    workdir = os.path.abspath("auto-syzkaller-%d" % (idx))

    logger.info('[+] workdir: %s', workdir)
    os.mkdir(workdir)
    return workdir


def setup_logging(debug: bool) -> None:
    """Sets logging level."""
    if debug:
        logging.basicConfig(
            level=logging.DEBUG,
            format=LOG_FMT,
            datefmt='%Y-%m-%d %H:%M:%S',
        )
    else:
        logging.basicConfig(
            level=logging.INFO,
            format=LOG_FMT,
            datefmt='%Y-%m-%d %H:%M:%S',
        )
    logger.debug("Logging level set")


def parse_args() -> argparse.Namespace:
    """CLI parser"""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--headers-file',
        '-f',
        help='File with list of headers from target compilation unit.',
        type=str)
    parser.add_argument('--kernel-folder',
                        '-k',
                        help='Path to kernel.',
                        type=str)

    parser.add_argument('--debug',
                        '-d',
                        help='Debug level logging.',
                        action='store_true')

    parser.add_argument('--target',
                        '-t',
                        help='The target .o file',
                        default=None)

    parser.add_argument(
        '--compare-to',
        '-c',
        help='Existing syzkaller description to compare findings to.',
        default=None)
    parser.add_argument('--coverage-report',
                        '-cr',
                        help='JSON file holding kernel coverage',
                        default='')

    args = parser.parse_args()
    return args


def extract_source_loc_analysis(workdir: str, all_sources: List[str],
                                report) -> None:
    """Extracts the lines of code in each C source code file."""
    all_c_files = fuzz_introspector_utils.get_all_c_files_mentioned_in_light(
        workdir, all_sources)
    logger.info('[+] Source files:')
    source_files = []
    total_loc = 0
    for c_file in all_c_files:
        logger.info('- %s', c_file)
        with open(c_file, 'r', encoding='utf-8') as f:
            content = f.read()
        loc = len(content.split('\n'))
        total_loc += loc
        source_files.append({'source': c_file, 'loc': loc})
    report['c_files'] = source_files
    report['loc'] = total_loc


def run_light_fi(target_dir, workdir, additional_files=None):
    """Light introspector run"""
    if not additional_files:
        additional_files = []
    logger.info('Running introspector on: %s', workdir)
    oss_fuzz.analyse_folder(language='c',
                            directory=target_dir,
                            entrypoint='',
                            out=workdir,
                            module_only=True,
                            files_to_include=additional_files)


def identify_kernel_source_files(kernel_folder) -> List[str]:
    """Identifies the source code files in the kernel and stores in
    global variable."""
    logger.info('Finding all header files')
    all_headers = textual_source_analysis.find_all_files_with_extension(
        kernel_folder, '.h')
    logger.info('Finding all source files')
    all_c_files = textual_source_analysis.find_all_files_with_extension(
        kernel_folder, '.c')
    all_sources = all_headers.union(all_c_files)

    textual_source_analysis.ALL_SOURCE_FILES = all_sources
    return all_sources


def get_possible_devnodes(ioctl_handlers):
    """Gets the devnodes of all ioctl handlers as a set."""
    all_devnodes = set()
    for ih in ioctl_handlers:
        for devnode in ih['possible-dev-names']:
            all_devnodes.add(devnode)
    logger.info('All possible dev nodes')
    for devnode in all_devnodes:
        logger.info('- %s', devnode)
    return all_devnodes


def analyse_ioctl_handler(ioctl_handler, workdir, kernel_folder, target_path):
    logger.info('- %s', ioctl_handler['func']['functionName'])

    # Get the next index that we will use to store data in the target
    # workdir.
    next_workdir_idx = syz_core.get_next_handler_workdir_idx(workdir)

    fi_data_dir = os.path.join(workdir,
                               'handler-analysis-%d' % (next_workdir_idx),
                               'fi-data')
    logger.info('Creating handler dir: %s', fi_data_dir)
    os.makedirs(fi_data_dir)

    # Extract the calltree. Do this by running an introspector run
    # to generate the calltree as well as analysis files.
    calltree = fuzz_introspector_utils.extract_calltree_light(
        ioctl_handler['func']['functionName'], kernel_folder, fi_data_dir,
        target_path)

    if calltree:
        ioctl_handler['calltree'] = calltree

        # Copy the calltree file to the already generated one. We need to
        # do this as otherwise the HTML report from Fuzz Introspector will
        # use a wrong calltree file.
        for filename in os.listdir(fi_data_dir):
            if filename.endswith('.data'):
                dst = os.path.join(workdir,
                                   'handler-analysis-%d' % (next_workdir_idx),
                                   'fi-data', filename)
                shutil.copy(os.path.join(fi_data_dir, 'targetCalltree.txt'),
                            dst)

        ryaml = os.path.join(workdir, 'report.yaml')
        if os.path.isfile(ryaml):
            shutil.copyfile(
                ryaml, os.path.join(fi_data_dir, 'fuzzerLogFile-0.data.yaml'))

        fcalltree = os.path.join(fi_data_dir, 'targetCalltree.txt')
        if os.path.isfile(fcalltree):
            shutil.copyfile(fcalltree,
                            os.path.join(fi_data_dir, 'fuzzerLogFile-0.data'))

        # Create Fuzz Introspector HTML report
        try:
            syz_core.create_fuzz_introspector_html_report(
                workdir, target_path, ioctl_handler['func']['functionName'],
                next_workdir_idx)
        except subprocess.CalledProcessError:
            pass

        # At this point, let's overwrite the calltree to show IOCTL locations.
        # Read the ioctl handler file
        # new_calltree = syz_core.highlight_ioctl_entrypoints_in_calltree(
        #    ioctl_handler, kernel_folder, calltree)
        ioctl_handler['calltree'] = calltree
    else:
        ioctl_handler['calltree'] = ''


def main() -> None:
    """Main entrypoint"""
    args = parse_args()
    setup_logging(args.debug)

    report: Dict[str, Any] = {}
    workdir = create_workdir()
    kernel_folder = os.path.abspath(args.kernel_folder)
    target_path = os.path.abspath(args.target)

    logger.info('Kernel folder: %s', kernel_folder)
    logger.info('Target: %s', target_path)

    if args.compare_to:
        print('[+] Parsing existing description %s', args.compare_to)
        existing_ioctl_commands = syz_core.parse_existing_description(
            args.compare_to)

    if args.coverage_report:
        os.environ['FI_KERNEL_COV'] = args.coverage_report

    # Extract source file structure.
    all_sources = identify_kernel_source_files(kernel_folder)

    # Run base introspector. In this run there are no entrypoints analysed.

    run_light_fi(target_path, workdir)
    extract_source_loc_analysis(workdir, all_sources, report)

    # Find all header files.
    logger.info('[+] Finding header files')
    report['header_files'] = syz_core.extract_header_files_referenced(
        workdir, all_sources)
    logger.info('Found a total of %d header files',
                len(report['header_files']))
    for header_file in report['header_files']:
        logger.info('- %s', header_file)

    new_headers = []
    logger.info('Refining header files')
    for header_file in report['header_files']:
        logger.info('r: %s', header_file)
        vt = textual_source_analysis.find_file(header_file)
        if vt:
            logger.info('--- %s', vt)
            new_headers.append(vt)
    logger.info('Refined to %d', len(new_headers))

    # Run the analysis again. This is needed to ensure the types from header
    # files are included in the analysis.
    run_light_fi(target_path, workdir, new_headers)

    # Extract ioctls.
    logger.info('[+] Extracting raw ioctls')
    report[
        'ioctls'] = textual_source_analysis.extract_raw_ioctls_text_from_header_files(
            report['header_files'], kernel_folder)

    for ioctl in report['ioctls']:
        logger.info('%s ::: %s', ioctl.raw_definition, ioctl.name)

    logger.info('[+] Scanning for ioctl handler using text analysis')
    ioctl_handlers = syz_core.get_ioctl_handlers(report['ioctls'],
                                                 kernel_folder, report,
                                                 workdir)

    # Get possible set of devnodes.
    all_devnodes = get_possible_devnodes(ioctl_handlers)

    report['ioctl_handlers'] = ioctl_handlers

    # extract calltrees
    for ioctl_handler in report['ioctl_handlers']:
        analyse_ioctl_handler(ioctl_handler, workdir, kernel_folder,
                              target_path)

    logger.info('[+] Showing complexity of ioctl handlers')
    syz_core.interpret_complexity_of_ioctl_handlers(report['ioctl_handlers'])

    logger.info('[+] Creating and dumping syzkaller description.')
    syz_core.create_and_dump_syzkaller_description(report['ioctls'], workdir,
                                                   all_devnodes, workdir,
                                                   target_path)

    logger.info('[+] Dumping full report.')
    syz_core.dump_report(workdir, report, args)

    if args.compare_to:
        logger.info('[+] Comparing analysis to existing description')
        syz_core.diff_analysis_to_existing_ioctl(existing_ioctl_commands,
                                                 report['all_ioctls'])


if __name__ == '__main__':
    main()
