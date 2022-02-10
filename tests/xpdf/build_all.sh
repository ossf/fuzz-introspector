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

export CFLAGS="$CFLAGS -fsanitize=fuzzer-no-link -fcommon -g  -flto  -flegacy-pass-manager "
export CXXFLAGS="$CXXFLAGS -fsanitize=fuzzer-no-link -fcommon -g -flto  -flegacy-pass-manager "
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

wget https://dl.xpdfreader.com/xpdf-latest.tar.gz
tar -zxf xpdf-latest.tar.gz
dir_name=`tar -tzf xpdf-latest.tar.gz | head -1 | cut -f1 -d"/"`
cd $dir_name

sed -i 's/#--- object files needed by XpdfWidget/add_library(testXpdfStatic STATIC $<TARGET_OBJECTS:xpdf_objs>)\n#--- object files needed by XpdfWidget/' ./xpdf/CMakeLists.txt

# Build the project
mkdir build
cd build
export LD=$CXX
cmake ../ -DCMAKE_C_FLAGS="$CFLAGS" -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
  -DOPI_SUPPORT=ON -DMULTITHREADED=0 -DCMAKE_DISABLE_FIND_PACKAGE_Qt4=1 \
  -DCMAKE_DISABLE_FIND_PACKAGE_Qt5Widgets=1 -DSPLASH_CMYK=ON
make -i || true

$RANLIB ./xpdf/libtestXpdfStatic.a
$RANLIB ./fofi/libfofi.a
$RANLIB ./goo/libgoo.a

# Build fuzzers
for fuzzer in zxdoc pdfload; do
    cp $SRC/fuzz_$fuzzer.cc .
    $CXX fuzz_$fuzzer.cc -o ./$fuzz_$fuzzer $CXXFLAGS $LIB_FUZZING_ENGINE \
      ./xpdf/libtestXpdfStatic.a ./fofi/libfofi.a ./goo/libgoo.a \
      -I../ -I../goo -I../fofi -I. -I../xpdf
done
