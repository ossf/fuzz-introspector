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
cd llvm-project
git checkout 2feddb37b48ea55f0d586d2710b9bc17f607e3e1
git apply --ignore-space-change --ignore-whitespace $BASE/llvm_diff.patch
#exit 0
cd ${BUILD_BASE}

# Now copy over the LLVM code we have
# This includes our inspector pass and the files included.
cp -rf ${BASE}/llvm/include/llvm/Transforms/Inspector/ ./llvm-project/llvm/include/llvm/Transforms//Inspector
cp -rf ${BASE}/llvm/lib/Transforms/Inspector ./llvm-project/llvm/lib/Transforms/Inspector


# Apply changes in the existing LLVM code. This is only
# to get our code integrated directly into Clang.
#echo "add_subdirectory(Inspector)" >> ./llvm-project/llvm/lib/Transforms/CMakeLists.txt
#sed -i 's/whole-program devirtualization and bitset lowering./whole-program devirtualization and bitset lowering.\nPM.add(createInspectorPass());/g' ./llvm-project/llvm/lib/Transforms/IPO/PassManagerBuilder.cpp
#sed -i 's/using namespace/#include "llvm\/Transforms\/Inspector\/Inspector.h"\nusing namespace/g' ./llvm-project/llvm/lib/Transforms/IPO/PassManagerBuilder.cpp

#sed -i 's/Instrumentation/Instrumentation\n  Inspector/g' ./llvm-project/llvm/lib/Transforms/IPO/CMakeLists.txt

# Build LLVM
mkdir llvm-build
cd llvm-build
cmake -G "Unix Makefiles" -DLLVM_ENABLE_PROJECTS="clang;compiler-rt"  \
      -DLLVM_BINUTILS_INCDIR=../binutils/include \
      -DLLVM_TARGETS_TO_BUILD="X86" ../llvm-project/llvm/
make llvm-headers
make -j5
make
