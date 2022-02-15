# Copyright 2022 Fuzz Introspector Authors
# Copyright 2020 Google Inc
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

set -x

BASE=$PWD
CLANG_BASE=${BASE}/../../build/llvm-build/bin/
export PATH=${CLANG_BASE}:${PATH}

export CC=clang
export CXX=clang++

export CFLAGS="$CFLAGS -fsanitize=fuzzer-no-link -fcommon -g  -flto "
export CXXFLAGS="$CXXFLAGS -fsanitize=fuzzer-no-link -fcommon -g -flto "
export LIB_FUZZING_ENGINE="-fsanitize=fuzzer  "
export LDFLAGS="-fuse-ld=gold"
export AR=llvm-ar
export RANLIB=llvm-ranlib
export CC=clang
export CXX=clang++
export SRC=$PWD


cd ${BASE}
rm -rf ./work
mkdir work
cd work

git clone --depth 1 https://github.com/RoaringBitmap/CRoaring croaring
cd croaring
mkdir build-dir && cd build-dir
cmake ..
make -j$(nproc)
$RANLIB ./tests/vendor/cmocka/example/mock/uptime/libproc_uptime.a
$RANLIB ./src/libroaring.a
$RANLIB ./src/libcmocka-static.a
make -j$(nproc)

$CC $CFLAGS  \
     -I../include \
     -c $SRC/croaring_fuzzer.c -o fuzzer.o
$CC $CFLAGS $LIB_FUZZING_ENGINE fuzzer.o   \
     -o ./croaring_fuzzer ./src/libroaring.a
