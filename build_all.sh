# Copyright 2021 Fuzz Introspector Authors
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

set -ex

BASE=$PWD
mkdir build
cd build
BUILD_BASE=$PWD

# Build  binutils
git clone --depth 1 git://sourceware.org/git/binutils-gdb.git binutils
mkdir build
cd ./build
../binutils/configure --enable-gold --enable-plugins --disable-werror
make all-gold
cd ${BUILD_BASE}

# Now build LLVM
git clone https://github.com/llvm/llvm-project/
cd llvm-project/

#git stash
git checkout release/14.x

$BASE/sed_cmds.sh
cd ${BUILD_BASE}

# Required for multicore support
python3 -m pip install psutil

# Now copy over the LLVM code we have
# This includes our inspector pass and the files included.
cp -rf ${BASE}/frontends/llvm/include/llvm/Transforms/FuzzIntrospector/ ./llvm-project/llvm/include/llvm/Transforms/FuzzIntrospector
cp -rf ${BASE}/frontends/llvm/lib/Transforms/FuzzIntrospector ./llvm-project/llvm/lib/Transforms/FuzzIntrospector

# Build LLVM
mkdir llvm-build
cd llvm-build
cmake -G "Unix Makefiles" -DLLVM_ENABLE_PROJECTS="clang;compiler-rt"  \
      -DLLVM_BINUTILS_INCDIR=../binutils/include \
      -DLLVM_TARGETS_TO_BUILD="X86" ../llvm-project/llvm/
make llvm-headers
make -j5
make
