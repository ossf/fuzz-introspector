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
