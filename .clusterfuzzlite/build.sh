#!/bin/bash -eu
pip3 install --upgrade pip
pip3 install --prefer-binary -r requirements.txt

cp src/test/fuzz/*.py .

hidden_imports="--hidden-import=yaml \
               --hidden-import=cxxfilt \
               --hidden-import=json \
               --hidden-import=bs4"
#fuzzers="test_fuzz_cfg_load.py test_fuzz_report_generation.py"
#fuzzers="test_fuzz_report_generation.py test_fuzz_report_generation.py"
#for fuzzer in $fuzzers; do
compile_python_fuzzer test_fuzz_report_generation.py -F --add-data "src/fuzz_introspector:fuzz_introspector" $hidden_imports
#done
