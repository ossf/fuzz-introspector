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
"""Helper methods related to syzkaller."""


def convert_raw_type_to_syzkaller_type(raw_type) -> str:
    """Converts type seen llvm ir/debug data to syzkaller type"""
    type_mapping = {
        '__u8': 'int8',
        '__s8': 'int8',
        'char': 'int8',
        'char *': 'int8',
        '__s16': 'int16',
        '__u16': 'int16',
        'short': 'int16',
        '__s32': 'int32',
        '__u32': 'int32',
        'int': 'int32',
        'int32_t': 'int32',
        'uint32_t': 'int32',
        'unsigned int': 'int32',
        '__s64': 'int64',
        '__u64': 'int64',
        '__u64 *': 'int64',
    }

    return type_mapping.get(raw_type, raw_type)


def get_type_ptr_of_syzkaller(ioctl) -> str:
    """Returns syzkaller type of an ioctl pointer."""
    return_type = 'arg ptr ['
    if ioctl.direction == 'IOWR':
        return_type += 'inout, '
    if ioctl.direction == 'IOW':
        return_type += 'in, '
    if ioctl.direction == 'IOR':
        return_type += 'out, '
    if ioctl.direction == 'IO':
        return_type += 'inout, '

    return_type += '%s]' % (convert_raw_type_to_syzkaller_type(
        ioctl.type.replace('struct', '').strip()))

    return return_type
