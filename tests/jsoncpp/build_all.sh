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

unset FUZZ_INTROSPECTOR

BASE=$PWD
CLANG_BASE=${BASE}/../../build/llvm-build/bin/
export PATH=${CLANG_BASE}:${PATH}

export AR=$CLANG_BASE/llvm-ar
export RANLIB=$CLANG_BASE/llvm-ranlib
export CC=clang
export CXX=clang++
export SRC=$PWD
export CC=clang
export CXX=clang++

cd ${BASE}
rm -rf ./work
mkdir work
cd work

export WDD=$PWD
export OUT=$WDD

#rm -rf ./libprotobuf-mutator
#rm -rf ./LPM
git clone --depth 1 https://github.com/google/libprotobuf-mutator.git
#mkdir LPM
#cd LPM 
#cmake ../libprotobuf-mutator -G "Unix Makefiles" -DCMAKE_VERBOSE_MAKEFILE:BOOL=ON -DCMAKE_AR=$AR -DCMAKE_RANLIB=$RANLIB -DLIB_PROTO_MUTATOR_DOWNLOAD_PROTOBUF=ON -DLIB_PROTO_MUTATOR_TESTING=OFF -DCMAKE_BUILD_TYPE=Release
#make V=1
mkdir LPM && cd LPM && cmake ../libprotobuf-mutator -GNinja -DLIB_PROTO_MUTATOR_DOWNLOAD_PROTOBUF=ON -DLIB_PROTO_MUTATOR_TESTING=OFF -DCMAKE_BUILD_TYPE=Release && ninja
cd $WDD


export CFLAGS="$CFLAGS -fsanitize=fuzzer-no-link -fcommon -g  -flto  "
export CXXFLAGS="$CXXFLAGS -fsanitize=fuzzer-no-link -fcommon -g -flto  "
export LIB_FUZZING_ENGINE="-fsanitize=fuzzer  "
export LDFLAGS="-fuse-ld=gold"

#exit 0

export FUZZ_INTROSPECTOR=1

git clone --depth 1 https://github.com/open-source-parsers/jsoncpp
#rm -rf ./build
mkdir -p build
cd build
cmake -DCMAKE_AR=$AR -DCMAKE_RANLIB=$RANLIB -DCMAKE_CXX_COMPILER=$CXX -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
      -DBUILD_SHARED_LIBS=OFF -G "Unix Makefiles" -DCMAKE_VERBOSE_MAKEFILE:BOOL=ON ../jsoncpp/
make V=1
# Compile fuzzer.
$CXX $CXXFLAGS -I../jsoncpp/include $LIB_FUZZING_ENGINE \
    ../jsoncpp/src/test_lib_json/fuzz.cpp -o $OUT/jsoncpp_fuzzer \
    lib/libjsoncpp.a

# Compile json proto.
rm -rf genfiles && mkdir genfiles && $WDD/LPM/external.protobuf/bin/protoc json.proto --cpp_out=genfiles --proto_path=$SRC

$CXX $CXXFLAGS -I genfiles -I../jsoncpp/ \
    -I.. \
    -I../../ \
    -I $WDD/libprotobuf-mutator/ \
    -I $WDD/LPM/external.protobuf/include -I ../jsoncpp/include $LIB_FUZZING_ENGINE \
    $SRC/jsoncpp_fuzz_proto.cc genfiles/json.pb.cc $SRC/json_proto_converter.cc \
    $WDD/LPM/src/libfuzzer/libprotobuf-mutator-libfuzzer.a \
    $WDD/LPM/src/libprotobuf-mutator.a \
    $WDD/LPM/external.protobuf/lib/libprotobuf.a \
    lib/libjsoncpp.a \
    -o  $OUT/jsoncpp_proto_fuzzer
