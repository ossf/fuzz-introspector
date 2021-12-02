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
git clone https://android.googlesource.com/platform/external/dng_sdk/
cd dng_sdk

# build project
cd ./source
rm dng_xmp*
find . -name "*.cpp" -exec $CXX $CXXFLAGS -DqDNGUseLibJPEG=1 -DqDNGUseXMP=0 -DqDNGThreadSafe=1 -c {} \;
${AR} cr libdns_sdk.a *.o

echo "[+] Now building the fuzzer"
# compile fuzzer
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE ../fuzzer/dng_parser_fuzzer.cpp -o dng_parser_fuzzer \
  ./libdns_sdk.a -I./ -l:libjpeg.a -lz
