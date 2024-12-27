#!/bin/bash -eu
python3 -m pip install --upgrade pip
python3 -m pip install jaraco.text==3.12.0
cd src
python3 -m pip install -e .
cd ../

cp src/test/fuzz/*.py .

hidden_imports="--hidden-import=yaml \
               --hidden-import=cxxfilt \
               --hidden-import=json \
               --hidden-import=bs4 \
               --hidden-import=tree_sitter \
               --hidden-import=tree_sitter_cpp \
               --hidden-import=tree_sitter_c \
               --hidden-import=tree_sitter_go \
               --hidden-import=tree_sitter_java \
               --hidden-import=pkg_resources.extern \
               --hidden-import=rust_demangler"
#fuzzers="test_fuzz_cfg_load.py test_fuzz_report_generation.py"
#fuzzers="test_fuzz_report_generation.py test_fuzz_report_generation.py"
#for fuzzer in $fuzzers; do
compile_python_fuzzer test_fuzz_report_generation.py -F --add-data "src/fuzz_introspector:fuzz_introspector" $hidden_imports
#done
