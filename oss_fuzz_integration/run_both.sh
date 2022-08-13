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

PROJ=$1
PORT=${FUZZ_INTROSPECTOR_PORT:-8008}

# Pass all arguments to get_full_coverage.py
python3 ${SCRIPT_DIR}/get_full_coverage.py $@
python3 ./infra/helper.py build_fuzzers --sanitizer=introspector $PROJ

LATEST_CORPUS_DIR=$(ls | grep "corpus-" | sed 's/corpus-//' | sort -n | tail -1)

cp -rf ./build/out/$PROJ/inspector/ ./corpus-$LATEST_CORPUS_DIR/inspector-report
cp -rf ./corpus-$LATEST_CORPUS_DIR/report/ ./corpus-$LATEST_CORPUS_DIR/inspector-report/covreport

# We need to allow the following to fail because it will do so for Python projects
cp -rf ./corpus-$LATEST_CORPUS_DIR/report_target/* ./corpus-$LATEST_CORPUS_DIR/inspector-report/covreport/ || true

echo "The following command is about to be run to start a webserver: cd ./corpus-${LATEST_CORPUS_DIR}/inspector-report/ && python3 -m http.server $PORT"
cd ./corpus-${LATEST_CORPUS_DIR}/inspector-report/
python3 -m http.server "$PORT"
