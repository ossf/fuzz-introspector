# Copyright 2024 Fuzz Introspector Authors
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
#
################################################################################

import argparse
import logging

import frontend_c, frontend_cpp, frontend_go

logger = logging.getLogger(name=__name__)
LOG_FMT = '%(asctime)s.%(msecs)03d %(levelname)s %(module)s - %(funcName)s: %(message)s'


def setup_logging():
    """Initializes logging"""
    logging.basicConfig(
        level=logging.INFO,
        format=LOG_FMT,
        datefmt='%Y-%m-%d %H:%M:%S',
    )


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser()

    parser.add_argument('--target-dir',
                        help='Directory of which do analysis',
                        required=True)
    parser.add_argument('--entrypoint',
                        help='Entrypoint for the calltree',
                        default='LLVMFuzzerTestOneInput')
    parser.add_argument('--language',
                        help='Language of target project',
                        required=True)
    return parser.parse_args()


def process_c_project(args):
    """Process a project in C language"""
    source_files = {}
    source_files['c'] = frontend_c.capture_source_files_in_tree(
        args.target_dir, 'c')
    logger.info('Found %d files to include in analysis',
                len(source_files['c']))
    logger.info('Loading tree-sitter trees')
    source_codes = frontend_c.load_treesitter_trees(source_files)

    logger.info('Creating base project.')
    project = frontend_c.Project(source_codes)
    project.dump_module_logic('report.yaml')

    if args.entrypoint != 'LLVMFuzzerTestOneInput':
        calltree_source = project.get_source_code_with_target(args.entrypoint)
        if calltree_source:
            calltree = project.extract_calltree(calltree_source,
                                                args.entrypoint)
            with open('targetCalltree.txt', 'w') as f:
                f.write(calltree)
    else:
        harnesses = []
        for idx, harness in enumerate(
                project.get_source_codes_with_harnesses()):
            logger.info('Extracting calltree for %s', harness.source_file)
            calltree = project.extract_calltree(harness, args.entrypoint)
            harnesses.append({'calltree': calltree})
            with open(f'fuzzer-calltree-{idx}', 'w', encoding='utf-8') as f:
                f.write(calltree)

        for idx, harness_dict in enumerate(harnesses):
            with open('fuzzer-calltree-%d' % (idx), 'w',
                      encoding='utf-8') as f:
                f.write(harness_dict['calltree'])


def process_cpp_project(args):
    """Process a project in CPP language"""
    source_files = {}
    source_files['cpp'] = frontend_cpp.capture_source_files_in_tree(
        args.target_dir, 'cpp')
    logger.info('Found %d files to include in analysis',
                len(source_files['cpp']))
    logger.info('Loading tree-sitter trees')
    source_codes = frontend_cpp.load_treesitter_trees(source_files)

    logger.info('Creating base project.')
    project = frontend_cpp.Project(source_codes)
    # project.dump_module_logic('report.yaml')
    for idx, harness in enumerate(project.get_source_codes_with_harnesses()):
        logger.info('Extracting calltree for %s', harness.source_file)

        calltree = project.extract_calltree(harness, args.entrypoint)
        logger.info('calltree: %s' % (calltree))


def process_go_project(args):
    """Process a project in Go language"""
    # Extract go source files
    logger.info('Going Go route')
    source_files = []
    source_files = frontend_go.capture_source_files_in_tree(args.target_dir)

    # Process tree sitter for go source files
    logger.info('Found %d files to include in analysis', len(source_files))
    logger.info('Loading tree-sitter trees')
    source_codes = frontend_go.load_treesitter_trees(source_files)

    # Create and dump project
    logger.info('Creating base project.')
    project = frontend_go.Project(source_codes)
    project.dump_module_logic('report.yaml')

    # Process calltree
    for idx, harness in enumerate(project.get_source_codes_with_harnesses()):
        logger.info('Extracting calltree for %s', harness.source_file)
        calltree = project.extract_calltree(harness.source_file, harness)
        with open(f'fuzzer-calltree-{idx}', 'w', encoding='utf-8') as f:
            f.write(calltree)


def main():
    """Main"""

    setup_logging()
    args = parse_args()

    if args.language == 'c':
        process_c_project(args)
    if args.language == 'cpp':
        process_cpp_project(args)
    if args.language == 'go':
        process_go_project(args)


if __name__ == "__main__":
    main()
