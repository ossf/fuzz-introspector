# Copyright 2021 Fuzz Introspector Authors
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

export FUZZ_INTROSPECTOR=1

rm -rf ./work
mkdir work
cd work

echo "[+] Linking the projects"
../../../build/llvm-build/bin/clang++ -v -fsanitize=fuzzer-no-link -g -c -flto  ../fuzzer.cpp -o fuzzer.o
echo "dos"
../../../build/llvm-build/bin/clang++ -v -fsanitize=fuzzer -g -flto  fuzzer.o -o fuzzer
echo "dres"
