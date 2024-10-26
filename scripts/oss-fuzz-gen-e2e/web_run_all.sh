#!/bin/bash -eux
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


ROOT_FI=$PWD/../../
BASE_DIR=$PWD/workdir
BENCHMARK_HEURISTICS="${VARIABLE:-far-reach-low-coverage,low-cov-with-fuzz-keyword,easy-params-far-reach}"
#BENCHMARK_HEURISTICS="${VARIABLE:-easy-params-far-reach}"
OFG_HARNESS_GENERATOR="${HARNESS_GENERATOR:-CSpecific}"
#OFG_HARNESS_GENERATOR="${HARNESS_GENERATOR:-Default}"
OSS_FUZZ_GEN_MODEL=${MODEL}
VAR_HARNESSES_PER_ORACLE="${HARNESS_PER_ORACLE:-40}"
VAR_LLM_FIX_LIMIT="${LLM_FIX_LIMIT:-2}"
PROJECT=${@}


if [[ -v OFGTT ]]; then
  echo "It's set"
  OFG_HARNESS_GENERATOR="${HARNESS_GENERATOR:-Default}"
  BENCHMARK_HEURISTICS="test-migration"
fi

echo "[+] Using generator: ${OFG_HARNESS_GENERATOR}"
echo "[+] Using heuristic: ${BENCHMARK_HEURISTICS}"
echo "[+] Using count: ${VAR_HARNESSES_PER_ORACLE}"
export OFG_USE_CACHING=1
export OSS_FI_TO_GET_TARGETS=1

comma_separated=""
for proj in ${PROJECT}; do
  echo ${proj}
  comma_separated="${comma_separated}${proj},"
done
comma_separated=${comma_separated::-1}

# Launch virtualenv
cd ${BASE_DIR}
. .venv/bin/activate

# Create webserver DB
echo "[+] Creating the webapp DB"
cd $ROOT_FI/tools/web-fuzzing-introspection/app/static/assets/db/
set -x
python3 ./web_db_creator_from_summary.py \
    --output-dir=$PWD \
    --input-dir=$PWD \
    --base-offset=0 \
    --includes=${comma_separated}

# Start webserver DB
echo "Shutting down server in case it's running"
curl --silent http://localhost:8080/api/shutdown || true

echo "[+] Launching FI webapp"
cd $ROOT_FI/tools/web-fuzzing-introspection/app/
FUZZ_INTROSPECTOR_SHUTDOWN=1 python3 ./main.py >> /dev/null &

SECONDS=5
while true
do
  # Checking if exists
  MSG=$(curl -v --silent 127.0.0.1:8080 2>&1 | grep "Fuzzing" | wc -l)
  if [[ $MSG > 0 ]]; then
    echo "Found it"
    break
  fi
  echo "- Waiting for webapp to load. Sleeping ${SECONDS} seconds."
  sleep ${SECONDS}
done

# Deactivate
echo "[+] Running OSS-Fuzz-gen experiment"
export LLM_FIX_LIMIT=${VAR_LLM_FIX_LIMIT}
cd $BASE_DIR/oss-fuzz-gen
./run_all_experiments.py \
    --model=$OSS_FUZZ_GEN_MODEL \
    -g ${BENCHMARK_HEURISTICS} \
    -gp ${comma_separated} \
    -gm ${VAR_HARNESSES_PER_ORACLE} \
    --prompt-builder ${OFG_HARNESS_GENERATOR} \
    -e http://127.0.0.1:8080/api

echo "Shutting down started webserver"
curl --silent http://localhost:8080/api/shutdown || true
