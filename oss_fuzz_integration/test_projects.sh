#!/bin/bash -u
#
# Copyright 2022 Fuzz Introspector Authors
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

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

for fuzzname in htslib kamailio orbit wuffs croaring nettle; do
  echo "Testing $fuzzname"
  python3 ${SCRIPT_DIR}/get_full_coverage.py $fuzzname 10 > get_coverage.log 2>&1
  python3 ./infra/helper.py build_fuzzers --sanitizer=instrumentor $fuzzname  > build_introspector.log 2>&1

  LATEST_CORPUS_DIR=$(ls | grep "corpus-" | sed 's/corpus-//' | sort -n | tail -1)

  cp -rf ./build/out/${fuzzname}/inspector-tmp/ ./corpus-$LATEST_CORPUS_DIR/inspector-report
  cp -rf ./corpus-$LATEST_CORPUS_DIR/report/ ./corpus-$LATEST_CORPUS_DIR/inspector-report/covreport

  mv get_coverage.log ./corpus-$LATEST_CORPUS_DIR/get_coverage.log
  mv build_introspector.log ./corpus-$LATEST_CORPUS_DIR/build_introspector.log

  # Look for the last logging statement of fuzz-introspector. If that statement is printed, then
  # it means no exceptions were thrown. This shows the build didn't crash.
  if [ $(grep "Ending fuzz introspector post-processing" ./corpus-$LATEST_CORPUS_DIR/build_introspector.log | wc -l) = 1 ]; then
    echo "Success"
  else
    echo "Failure"
  fi
done
