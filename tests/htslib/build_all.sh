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
CLANG_BASE=${BASE}/../../build/llvm-build/bin/
export PATH=${CLANG_BASE}:${PATH}

export CC=clang
export CXX=clang++

export CFLAGS="$CFLAGS -fsanitize=fuzzer-no-link -fcommon -g  -flto -flegacy-pass-manager "
export CXXFLAGS="$CXXFLAGS -fsanitize=fuzzer-no-link -fcommon -g -flto -flegacy-pass-manager "
export LIB_FUZZING_ENGINE="-fsanitize=fuzzer "
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


# OSS-Fuzz build.
git clone --depth 1 --shallow-submodules --recurse-submodules https://github.com/samtools/htslib
cd htslib

# build project
autoconf
autoheader
./configure
make -j$(nproc) libhts.a
make test/fuzz/hts_open_fuzzer.o 

echo "[+] Now building the fuzzer"

# build fuzzers
$CXX $CXXFLAGS test/fuzz/hts_open_fuzzer.o $LIB_FUZZING_ENGINE libhts.a -lz -lbz2 -llzma -lcurl -lcrypto -lpthread
