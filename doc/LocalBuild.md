# Build locally

This document describes how to build Fuzz Introspector outside the OSS-Fuzz environment.

# TLDR:
```bash
git clone https://github.com/ossf/fuzz-introspector
cd fuzz-introspector

# Get python dependencies
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt

# Build custom clang with Fuzz introspector LLVM pass
./build_all.sh

cd tests
./build_simple_example.sh
cd simple-example-0/web
python3 -m http.server 8008
```

## Use Docker

Will use sources cloned to /your/path/to/source

```
docker build  -t "fuzz-introspector:Dockerfile" .
docker run --rm -it -v /your/path/to/source:/src fuzz-introspector:Dockerfile

```

## Full process


### step 1: Start a python venv
```bash
git clone https://github.com/ossf/fuzz-introspector

# create virtual environment
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

### step 2: Build custom clang
Fuzz-introspector relies on an LTO LLVM pass and this requires us to build a custom Clang where the LTO pass is part of the compiler tool chain (see https://github.com/ossf/fuzz-introspector/issues/57 for more details on why this is needed).

To build the custom clang from the root of this repository:

```bash
mkdir build
cd build

# Build binutils
apt install texinfo
git clone --depth 1 git://sourceware.org/git/binutils-gdb.git binutils
mkdir build
cd ./build
../binutils/configure --enable-gold --enable-plugins --disable-werror
make all-gold
cd ../

# Build LLVM and Clang
git clone https://github.com/llvm/llvm-project/
cd llvm-project/
git checkout release/15.x

# Patch Clang to run fuzz introspector
../../frontends/llvm/patch-llvm.sh
cp -rf ../../frontends/llvm/include/llvm/Transforms/FuzzIntrospector/ ./llvm/include/llvm/Transforms/FuzzIntrospector
cp -rf ../../frontends/llvm/lib/Transforms/FuzzIntrospector ./llvm/lib/Transforms/FuzzIntrospector
cd ../

# Build LLVM and clang
mkdir llvm-build
cd llvm-build
cmake -G "Unix Makefiles" -DLLVM_ENABLE_PROJECTS="clang;compiler-rt"  \
      -DCMAKE_BUILD_TYPE=Debug \
      -DLLVM_BINUTILS_INCDIR=../binutils/include \
      -DLLVM_TARGETS_TO_BUILD="X86" ../llvm-project/llvm/
make llvm-headers
make -j5
```

##### step 3: Run local example

Now we have two options, to run the fuzz introspector tools without collecting
runtime coverage and doing it with collecting coverage. We go through each of the two options:

##### step 3, option 1, only static analysis
After having built the custom clang above, you build a test case:
```
# From the root of the fuzz-introspector repository
cd tests/simple-example-0

# Run compiler pass to generate *.data and *.data.yaml files
mkdir work
cd work
FUZZ_INTROSPECTOR=1 ../../../build/llvm-build/bin/clang -fsanitize=fuzzer -fuse-ld=gold -flto -g ../fuzzer.c -o fuzzer

# Run post-processing to analyse data files and generate HTML report
python3 ../../../src/main.py correlate --binaries_dir=.
python3 ../../../src/main.py report --target_dir=. --correlation_file=./exe_to_fuzz_introspector_logs.yaml

# The post-processing will have generated various .html, .js, .css and .png fies,
# and these are accessible in the current folder. Simply start a webserver and 
# navigate to the report in your local browser (localhost:8008):
python3 -m http.server 8008
```


##### step 3, option 2, include runtime coverage analysis
```
# From the root of the fuzz-introspector repository
cd tests/simple-example-0

# Run compiler pass to generate *.data and *.data.yaml files
mkdir work
cd work

# Run script that will build fuzzer with coverage instrumentation and extract .profraw files
# and convert those to .covreport files with "llvm-cov show"
../build_cov.sh

# Build fuzz-introspector normally
FUZZ_INTROSPECTOR=1 ../../../build/llvm-build/bin/clang -fsanitize=fuzzer -fuse-ld=gold -flto -g ../fuzzer.c -o fuzzer

# Run post-processing to analyse data files and generate HTML report
python3 ../../../src/main.py correlate --binaries_dir=.
python3 ../../../src/main.py report --target_dir=. --correlation_file=./exe_to_fuzz_introspector_logs.yaml

# The post-processing will have generated various .html, .js, .css and .png fies,
# and these are accessible in the current folder. Simply start a webserver and
# navigate to the report in your local browser (localhost:8008):
python3 -m http.server 8008
```

You can also use the `build_all_projects.sh` and `build_all_web_only.sh` scripts to control
which examples you want to build as well as whether you want to only build the web data.

