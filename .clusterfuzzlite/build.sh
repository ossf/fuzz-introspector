#!/bin/bash -eu
pip3 install --upgrade pip
pip3 install -r requirements.txt
pip3 install pyyaml

cp src/test/fuzz/*.py .

hidden_imports="--hidden-import=yaml \
               --hidden-import=cxxfilt \
               --hidden-import=json \
               --hidden-import=bs4 \
               --hidden-import=matplotlib"
fuzzers="fuzz_cfg_load.py fuzz_report_generation.py"
for fuzzer in $fuzzers; do
  compile_python_fuzzer $fuzzer -F --add-data "src/fuzz_introspector:fuzz_introspector" $hidden_imports
done
