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
