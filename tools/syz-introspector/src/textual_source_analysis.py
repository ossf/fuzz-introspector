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
"""
Utilities for analysing source code purely based on textual analysis.
"""

import os
import logging

from typing import List, Optional, Set

ALL_SOURCE_FILES: Set[str] = set()


class IOCTL:

    def __init__(self, definition_src_file_full, definition_src_file,
                 definition_src_line, raw_definition):
        self.definition_src_file = definition_src_file
        self.definition_src_file_full = definition_src_file_full
        self.definition_src_line = definition_src_line
        self.raw_definition = raw_definition

        self.name = ''
        self.type = ''
        self.direction = ''
        self.deconstruct_ioctl()

    def is_valid(self):
        return self.name != ''

    def to_dict(self):
        return {
            'name': self.name,
            'type': self.type,
            'direction': self.direction,
            'src_line': self.definition_src_line,
            'src_file': self.definition_src_file_full
        }

    def __str__(self):
        return 'IOCTL: {"name" : "%s", "type": "%s", "direction": "%s"}' % (
            self.name, self.type, self.direction)

    def deconstruct_ioctl(self) -> bool:
        """Given a textual definition of an IOCTL, decomposes this into a more
        clear object."""
        ioctl_def = self.raw_definition.replace("\n", "")

        # If there is a single left paren and right paren, and two commas, then
        # it's a straightforward definition to pass.
        if ioctl_def.count('(') == 1 and ioctl_def.count(
                ')') == 1 and ioctl_def.count(',') == 2:
            # Identify types
            type_section = ioctl_def.split('(')[-1].split(')')[0]
            ioctl_type = type_section.split(',')[2].replace('*', '').strip()

            # Extract the ioctl name
            ioctl_name = ioctl_def.split('(')[0].replace('#define', '').strip()
            if len(ioctl_name.split(' ')) > 0:
                ioctl_name = ioctl_name.split(' ')[0]
            if len(ioctl_name.split('\t')) > 0:
                ioctl_name = ioctl_name.split('\t')[0]

            # Extract the specific type of IOW
            ioctl_direction = None
            if '_IOWR' in ioctl_def:
                ioctl_direction = 'IOWR'
            elif '_IOR' in ioctl_def:
                ioctl_direction = 'IOR'
            elif '_IOW' in ioctl_def:
                ioctl_direction = 'IOW'
            elif '_IO' in ioctl_def:
                ioctl_direction = 'IO'

            self.name = ioctl_name
            self.type = ioctl_type
            self.direction = ioctl_direction
            return True
        return False


def scan_line_for_ioctl(idx: int, split_lines: List[str]) -> Optional[str]:
    """Determines whether line `idx` contains an ioctl
    definition. This includes multi-line definitions, which is searched
    for in the event an IOCTL-relevant maro is found.

    Returns the lines declaring the ioctl if found, and None otherwise.
    """
    line = split_lines[idx]

    ioctl_defs = ['_IOWR(', '_IO(', '_IOW(', '_IOR(']
    if not (any(ioctl in line for ioctl in ioctl_defs)):
        return None

    # IOCTL macro was found, it's likely this is a IOCTL definition
    # but not yet guaranteed.
    ioctl_def = line

    # Ensure #define is there.
    if 'define' not in line:
        # Look for earlier lines
        sl_m1 = split_lines[idx - 1]
        if 'define' in sl_m1:
            ioctl_def = sl_m1 + '\n' + line
        else:
            sl_m2 = split_lines[idx - 2]
            if 'define' in sl_m2:
                ioctl_def = sl_m1 + "\n" + sl_m2 + "\n" + line

    # No define, no ioctl.
    if 'define' not in ioctl_def:
        return None

    # Ensure there is whitespace between ioctls, e.g.
    # invalid ioctl: "// void print_fnc_IOWR(..)"
    # valid ioctl:   #define _IOWR(
    no_newlines = ioctl_def.replace('\n', '')
    if not (any(' %s' % (ioctl) in no_newlines
                for ioctl in ioctl_defs)) and not (any(
                    '\t%s' % (ioctl) in no_newlines for ioctl in ioctl_defs)):
        return None

    # Check if we're inside a comment.
    if no_newlines.replace(' ', '').replace('\t', '').startswith("*"):
        return None

    return ioctl_def


def scan_file_for_ioctls(file_to_scan: str, basefolder: str) -> List[IOCTL]:
    """Scans a file for IOCTL macro definitions.

    Returns the raw lines where ioctls are defined.
    """
    ioctl_lines: List[IOCTL] = []

    # Adjust to basefolder
    if not os.path.isfile(file_to_scan):
        file_path = basefolder + '/' + file_to_scan
    else:
        file_path = file_to_scan

    if not os.path.isfile(file_path):
        logging.debug('Could not find file: %s', file_path)
        return ioctl_lines

    with open(file_path, 'r') as file_fd:
        file_content = file_fd.read()
    file_lines = file_content.split('\n')

    # Iterate lines to find ioctl.
    for idx in range(len(file_lines)):
        ioctl_def = scan_line_for_ioctl(idx, file_lines)
        if ioctl_def:
            discovered_ioctl = IOCTL(definition_src_file_full=file_path,
                                     definition_src_file=file_to_scan,
                                     definition_src_line=idx,
                                     raw_definition=ioctl_def)
            if not discovered_ioctl.is_valid():
                continue

            ioctl_lines.append(discovered_ioctl)
    return ioctl_lines


def find_file(target_file: str) -> str:
    """Finds a file amongst all source files. Uses heuristics to improve
    matching."""
    logging.debug('Target f: %s' % (target_file))
    suffix_path = target_file.split('../')[-1]
    logging.debug('suffix_path: %s' % (suffix_path))
    if len(suffix_path) < 2:
        raise Exception("Filename too short")
    matching_files = set()
    for source_file in ALL_SOURCE_FILES:
        if source_file.endswith(suffix_path):
            matching_files.add(source_file)
        elif source_file.endswith(('/').join(suffix_path.split('/')[-4:])):
            matching_files.add(source_file)
        elif source_file.endswith(('/').join(suffix_path.split('/')[-3:])):
            matching_files.add(source_file)
    if not matching_files:
        if os.path.isabs(target_file) and os.path.isfile(target_file):
            matching_files.add(target_file)

    if not matching_files:
        logging.info('Did not find %s' % (target_file))
        return ''

    if len(matching_files) == 1:
        return matching_files.pop()

    # We found more than 1 matching file. Try and filter based on
    # common patterns.
    src_files_without_out = []
    for src_file in matching_files:
        if '/out/' not in src_file:
            src_files_without_out.append(src_file)
    if len(src_files_without_out) == 1:
        return src_files_without_out[0]

    logging.debug('Matching files: %s' % (matching_files))

    # We could do a loti more here, but am not sure if we want to start
    # doing that.
    logging.debug('Error: cannot find %s' % (target_file))
    # logging.info('Found: %s' % (str(list(matching_files))))
    return ''


def extract_raw_ioctls_text_from_header_files(
        all_header_files: List[str], kernel_folder: str) -> list[IOCTL]:
    """Scans a list of header files and finds the lines of code having IOCTL
    definitions."""
    ioctls = []
    for header_file in all_header_files:
        logging.debug('Analysing: %s' % (header_file))
        # Get the path after last relative
        refined_path = find_file(header_file)
        logging.debug('Refined path: %s' % (refined_path))
        if refined_path:
            discovered_ioctls = scan_file_for_ioctls(refined_path,
                                                     kernel_folder)
            ioctls += discovered_ioctls
            if discovered_ioctls:
                continue

    logging.info('Found %d ioctls', len(ioctls))

    logging.info('[+] Found ioctl macro defintions')
    for ioctl in ioctls:
        logging.info('- %s : %s', ioctl.definition_src_file,
                     ioctl.raw_definition)
    return ioctls


def find_basefile_in_kernel(kernel_folder: str, basename: str) -> str:
    """Goes through the kernel source code to find a basename."""
    for root, dirs, files in os.walk(kernel_folder):
        for filename in files:
            if basename == filename:
                return os.path.join(root, filename)
    return ''


def get_possible_devnames(source_file: str, kernel_folder: str) -> List[str]:
    """Reads a source file and scans for possible devnames."""

    logging.info('Finding possible dev nodes: %s', source_file)
    possible_dev_names = set()
    if not os.path.isfile(source_file):
        refined_source_file = find_basefile_in_kernel(
            kernel_folder, os.path.basename(source_file))
        if not refined_source_file:
            return []
        source_file = refined_source_file

    with open(source_file, 'r') as f:
        for line in f:
            if '.name =' in line:
                print(line)
                split_line = line.split('.name =')
                print(split_line)
                print(split_line[-1].split('"'))
                try:
                    possible_dev_name = split_line[-1].split('"')
                    print('-' * 30)
                    print(possible_dev_name[1])
                    possible_dev_names.add(possible_dev_name[1])
                except (IndexError, KeyError):
                    pass
    print("List of possible dev names")
    print(list(possible_dev_names))
    return list(possible_dev_names)


def find_all_files_with_extension(kernel_folder, extension) -> Set[str]:
    extension_files = set()
    for path, folders, files in os.walk(kernel_folder):
        for file in files:
            if os.path.splitext(file)[1] == extension:
                extension_files.add(os.path.join(path, file))
    return extension_files
