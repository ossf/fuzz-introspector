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


def convert_raw_type_to_syzkaller_type(raw_type):
    if raw_type == '__s32':
        return 'int32'
    if raw_type == '__u32':
        return 'int32'
    if raw_type == 'unsigned int':
        return 'int32'
    if raw_type == '__u64':
        return 'int64'
    if raw_type == 'int32_t' or raw_type == 'int':
        return 'int32'
    if raw_type == 'uint32_t':
        return 'int32'
    if raw_type == '__u64 *':
        return 'int64'
    if raw_type == 'char *':
        return 'int8'
    if raw_type == 'char':
        return 'int8'
    if raw_type == '__u16':
        return 'int16'
    return raw_type


def get_type_ptr_of_syzkaller(ioctl):
    returnType = 'arg ptr ['
    if ioctl.direction == 'IOWR':
        returnType += 'inout, '
    if ioctl.direction == 'IOW':
        returnType += 'in, '
    if ioctl.direction == 'IOR':
        returnType += 'out, '
    if ioctl.direction == 'IO':
        returnType += 'inout, '

    returnType += '%s]' % (convert_raw_type_to_syzkaller_type(
        ioctl.type.replace('struct', '').strip()))

    return returnType


def is_basic_type(typename):
    basic_types = {'int8', 'int32', 'ptr [in, int8]'}
    return typename in basic_types


def is_raw(typename):
    return 'DW_TAG' in typename
