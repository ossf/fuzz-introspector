# Copyright 2024 Fuzz Introspector Authors
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

#rm -rf ./work_cov
#mkdir work_cov
#cd work_cov
if [ -d "work" ]; then
    cd work
fi

../../../build/llvm-build/bin/clang -fprofile-instr-generate -fcoverage-mapping -fsanitize=fuzzer -g ../fuzzer.c -o fuzzer
./fuzzer -max_total_time=3
../../../build/llvm-build/bin/llvm-profdata merge -sparse default.profraw -o merged_cov.profdata
../../../build/llvm-build/bin/llvm-cov show -instr-profile=merged_cov.profdata -object=./fuzzer -line-coverage-gt=0 > fuzzer.covreport
