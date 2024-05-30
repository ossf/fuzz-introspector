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

BASE_DIR=$PWD                                                                  
FI_DIR=$BASE_DIR/fuzz-introspector/
PROJECT=${PROJECT}
OSS_FUZZ_GEN_MODEL=${MODEL}
# Launch virtualenv
. .venv/bin/activate

cd $FI_DIR/oss_fuzz_integration/oss-fuzz                                        
python3 ../runner.py introspector $PROJECT 10 --disable-webserver                
                                                                               
                                                                               
# Create webserver DB                                                          
cd $FI_DIR/tools/web-fuzzing-introspection/app/static/assets/db/
python3 ./web_db_creator_from_summary.py \
    --local-oss-fuzz $FI_DIR/oss_fuzz_integration/oss-fuzz                      
                                                                               
# Start webserver DB                                                            
echo "Shutting down server in case it's running"
curl --silent http://localhost:8080/api/shutdown || true

echo "Launching FI webapp"
cd $FI_DIR/tools/web-fuzzing-introspection/app/                                
FUZZ_INTROSPECTOR_LOCAL_OSS_FUZZ=$FI_DIR/oss_fuzz_integration/oss-fuzz \
  python3 ./main.py >> /dev/null &
                                                                               
SECONDS=5
while true
do
  # Checking if exists
  MSG=$(curl -v --silent 127.0.0.1:8080 2>&1 | grep "Fuzzing" | wc -l)
  if [[ $MSG > 0 ]]; then
    echo "Found it"
    break
  fi
  echo "Sleeping"
  sleep ${SECONDS}

done

# Deactivate
echo "Running OSS-Fuzz-gen experiment"
cd $BASE_DIR/oss-fuzz-gen
./run_all_experiments.py \
  --model=$OSS_FUZZ_GEN_MODEL \
  -g low-cov-with-fuzz-keyword,far-reach-low-coverage \
  -gp $PROJECT \
  -gm 6 \
  -e http://127.0.0.1:8080/api

echo "Shutting down started webserver"
curl --silent http://localhost:8080/api/shutdown || true
