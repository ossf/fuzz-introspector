#!/bin/bash -eu
pip3 install --upgrade pip
pip3 install --prefer-binary -r requirements.txt

cp src/test/fuzz/*.py .

hidden_imports="--hidden-import=yaml \
               --hidden-import=cxxfilt \
               --hidden-import=json \
               --hidden-import=bs4 \
               --hidden-import=matplotlib"
fuzzers="test_fuzz_cfg_load.py test_fuzz_report_generation.py"
for fuzzer in $fuzzers; do
  compile_python_fuzzer $fuzzer -F --add-data "src/fuzz_introspector:fuzz_introspector" $hidden_imports
done
