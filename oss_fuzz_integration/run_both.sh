#!/bin/bash -eu
#
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

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
python3 ${SCRIPT_DIR}/get_full_coverage.py $1 $2
python3 ./infra/helper.py build_fuzzers --sanitizer=instrumentor $1

LATEST_CORPUS_DIR=$(ls | grep "corpus-" | sed 's/corpus-//' | sort -n | tail -1)

cp -rf ./build/out/$1/inspector-tmp/ ./corpus-$LATEST_CORPUS_DIR/inspector-report
cp -rf ./corpus-$LATEST_CORPUS_DIR/report/ ./corpus-$LATEST_CORPUS_DIR/inspector-report/covreport

echo "If all worked, then you should be able to start a webserver at port 8008 in ./corpus-${LATEST_CORPUS_DIR}/inspector-report/"
