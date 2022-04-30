#!/bin/bash -eux
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

# create next test report directory
TEST_REPORT_NAME="test-report-"
if [ $(ls | grep $TEST_REPORT_NAME | wc -l) -gt 0 ]; then
  LATEST_TEST_DIR_NUM=$(ls | grep "$TEST_REPORT_NAME" | sed "s/$TEST_REPORT_NAME//" | sort -n | tail -1)

else
  LATEST_TEST_DIR_NUM=0
fi
NEW_TEST_COUNT=$(($LATEST_TEST_DIR_NUM+1))
NEW_TEST_DIR="$TEST_REPORT_NAME$NEW_TEST_COUNT"
echo "NEW_TEST_DIR: $NEW_TEST_DIR"
mkdir $NEW_TEST_DIR

for fuzzname in htslib unrar jsoncpp; do
  echo "Testing $fuzzname"
  python3 ${SCRIPT_DIR}/get_full_coverage.py $fuzzname 10 > get_coverage.log 2>&1
  python3 ./infra/helper.py build_fuzzers --sanitizer=introspector $fuzzname  > build_introspector.log 2>&1

  LATEST_CORPUS_DIR=$(ls | grep "corpus-" | sed 's/corpus-//' | sort -n | tail -1)

  cp -rf ./build/out/${fuzzname}/inspector/ ./corpus-$LATEST_CORPUS_DIR/inspector-report
  cp -rf ./corpus-$LATEST_CORPUS_DIR/report/ ./corpus-$LATEST_CORPUS_DIR/inspector-report/covreport
  cp -rf ./corpus-$LATEST_CORPUS_DIR/report_target/* ./corpus-$LATEST_CORPUS_DIR/inspector-report/covreport/

  mv get_coverage.log ./corpus-$LATEST_CORPUS_DIR/get_coverage.log
  mv build_introspector.log ./corpus-$LATEST_CORPUS_DIR/build_introspector.log
  echo "$fuzzname" >> ./corpus-$LATEST_CORPUS_DIR/project_name

  # Look for the last logging statement of fuzz-introspector. If that statement is printed, then
  # it means no exceptions were thrown. This shows the build didn't crash.
  if [ $(grep "Ending fuzz introspector post-processing" ./corpus-$LATEST_CORPUS_DIR/build_introspector.log | wc -l) -gt 0 ]; then
    echo "Success"
  else
    echo "Failure"
  fi

  # Now copy the data into the test directory
  cp -rf ./corpus-$LATEST_CORPUS_DIR $NEW_TEST_DIR/
done

python3 $SCRIPT_DIR/project-checker.py --test-dir=$NEW_TEST_DIR/
