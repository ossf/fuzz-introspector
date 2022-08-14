#!/bin/bash -u
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

ROOT=$PWD
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'
export FUZZ_INTROSPECTOR=1
for PROJ in simple-example-0 simple-example-1 simple-example-2 simple-example-3 simple-example-4 simple-example-indirect-pointers cpp-simple-example-1; do
  echo "Testing $PROJ"
  cd ${ROOT}/${PROJ}
  rm -rf ./web

  # Check compilation
  ./build_all.sh > log_compilation.txt 2>&1
  retval=$?
  if [ $retval -ne 0 ]; then
    echo -e "${RED}[-] fail: compilation${NC}"
    continue
  fi
  
  # Check post-processing
  mkdir web
  cd web
  python3 ${ROOT}/../src/main.py report --target_dir=../ > log_post-processing.txt 2>&1
  retval=$?
  if [ $retval -ne 0 ]; then
    echo -e "${RED}[-] fail: post-processing${NC}"
    continue
  fi

  echo -e "${GREEN}[+] success${NC}"
done
