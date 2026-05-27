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
BUILD_BASE=$BASE/build

if [ -d "$BUILD_BASE/llvm-project" ] && [ -d "$BUILD_BASE/llvm-build" ]; then
  echo "Reusing set up (LLVM Source). Updating the LLVM plugin"
  rm -rf $BUILD_BASE/llvm-project/llvm/include/llvm/Transforms/FuzzIntrospector
  rm -rf $BUILD_BASE/llvm-project/llvm/lib/Transforms/FuzzIntrospector
  cp -rf ${BASE}/frontends/llvm/include/llvm/Transforms/FuzzIntrospector/ $BUILD_BASE/llvm-project/llvm/include/llvm/Transforms/FuzzIntrospector
  cp -rf ${BASE}/frontends/llvm/lib/Transforms/FuzzIntrospector $BUILD_BASE/llvm-project/llvm/lib/Transforms/FuzzIntrospector

  # Recreate build dir if it was generated with a different CMake generator.
  if [ -f "$BUILD_BASE/llvm-build/CMakeCache.txt" ] && \
     grep -q 'CMAKE_GENERATOR:INTERNAL=Unix Makefiles' "$BUILD_BASE/llvm-build/CMakeCache.txt"; then
    echo "Existing llvm-build uses Unix Makefiles; recreating for Ninja"
    rm -rf "$BUILD_BASE/llvm-build"
    mkdir "$BUILD_BASE/llvm-build"
  fi

  cd $BUILD_BASE/llvm-build
  cmake -G Ninja \
        -DLLVM_ENABLE_PROJECTS="clang;lld;compiler-rt" \
        -DCMAKE_BUILD_TYPE=Release \
        -DLLVM_TARGETS_TO_BUILD="X86" \
        -DLLVM_ENABLE_RTTI=ON \
        -DLLVM_INCLUDE_TESTS=OFF \
        -DLLVM_INCLUDE_BENCHMARKS=OFF \
        ../llvm-project/llvm/
  ninja clang lld compiler-rt
else
  echo "Cloning and building LLVM from scratch."
  mkdir -p $BUILD_BASE

  # Now build LLVM
  cd ${BUILD_BASE}
  git clone https://github.com/llvm/llvm-project/
  cd llvm-project/
  git checkout llvmorg-22.1.0

  echo "Applying diffs to insert Fuzz Introspector plugin in the LLVM pipeline"
  $BASE/frontends/llvm/patch-llvm.sh

  # Now copy over the LLVM code we have
  # This includes our inspector pass and the files included.
  cp -rf ${BASE}/frontends/llvm/include/llvm/Transforms/FuzzIntrospector/ ${BUILD_BASE}/llvm-project/llvm/include/llvm/Transforms/FuzzIntrospector
  cp -rf ${BASE}/frontends/llvm/lib/Transforms/FuzzIntrospector ${BUILD_BASE}/llvm-project/llvm/lib/Transforms/FuzzIntrospector

  # Build LLVM
  cd ${BUILD_BASE}
  mkdir llvm-build
  cd llvm-build
  cmake -G Ninja \
        -DLLVM_ENABLE_PROJECTS="clang;lld;compiler-rt" \
        -DCMAKE_BUILD_TYPE=Release \
        -DLLVM_TARGETS_TO_BUILD="X86" \
        -DLLVM_ENABLE_RTTI=ON \
        -DLLVM_INCLUDE_TESTS=OFF \
        -DLLVM_INCLUDE_BENCHMARKS=OFF \
        ../llvm-project/llvm/
  ninja clang lld compiler-rt
fi
