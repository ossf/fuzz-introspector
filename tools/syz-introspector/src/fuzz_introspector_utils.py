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

import os
import shutil
import logging
from typing import List

import yaml
from fuzz_introspector.frontends import oss_fuzz

import textual_source_analysis

logger = logging.getLogger(name=__name__)


def get_light_functions(workdir):
    with open(os.path.join(workdir, 'report.yaml'), 'r',
              encoding='utf-8') as f:
        contents = yaml.safe_load(f)
    return contents['All functions']['Elements']


def get_source_to_functions_mapping(all_functions):
    """Creates a mapping of source file to functions based of the
    Fuzz Introspector function list. This is useful to quickly do look-ups
    on functions related to a given source file."""
    all_files_with_func = dict()
    for func in all_functions:
        try:
            source_file = func['functionSourceFile']
            source_line = func.get('func_position')['start']
        except IndexError:
            continue

        func['analysis'] = {
            'source_file': source_file,
            'source_line': int(source_line)
        }

        if source_file not in all_files_with_func:
            all_files_with_func[source_file] = list()

        all_files_with_func[source_file].append(func)
    return all_files_with_func


def copy_introspector_artifacts(src_dir, dst_dir):
    # Copy in the generated introspector files
    for filename in os.listdir(src_dir):
        if filename.startswith('fuzzerLogFile-'):
            shutil.copy(filename, os.path.join(dst_dir, filename))


def cleanup_files(workdir: str = ""):
    """Cleaning up the working directory"""

    for filename in os.listdir(os.getcwd()):
        if filename.startswith('fuzzerLogFile-'):
            os.remove(filename)
    if os.path.isfile('./tmp.bc'):
        if workdir:
            shutil.copy('tmp.bc', os.path.join(workdir, 'tmp.bc'))
        os.remove('tmp.bc')
    if os.path.isfile('targetCalltree.txt'):
        os.remove('targetCalltree.txt')


def get_all_c_files_mentioned_in_light(workdir, all_source) -> List[str]:
    with open(os.path.join(workdir, 'report.yaml'), 'r',
              encoding='utf-8') as f:
        content = yaml.safe_load(f)
    all_files = []
    for source_file in content['sources']:
        if source_file['source_file'].endswith('.c'):
            all_files.append(source_file['source_file'])
    return all_files


def get_all_header_files_in_light(workdir, all_sources) -> List[str]:
    all_header_files = []
    with open(os.path.join(workdir, 'report.yaml'), 'r',
              encoding='utf-8') as f:
        content = yaml.safe_load(f)
    header_files = content.get('included-header-files', [])
    for h in header_files:
        logger.debug('Finding file %s', h)
        header_path = textual_source_analysis.find_file(h)
        if header_path:
            all_header_files.append(header_path)
    return all_header_files


def extract_calltree_light(target_function, kernel_dir, workdir, target_dir):
    """Light introspector run"""

    # logging.info('Analysing: %s' % (workdir))
    oss_fuzz.analyse_folder('c', target_dir, target_function, workdir)
    calltree_file = os.path.join(workdir, 'targetCalltree.txt')
    if os.path.isfile(calltree_file):
        with open(calltree_file, 'r', encoding='utf-8') as f:
            calltree = f.read()
        return calltree
    return None
