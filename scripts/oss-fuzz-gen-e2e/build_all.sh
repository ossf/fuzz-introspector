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
mkdir -p workdir
cd workdir
WORKDIR=$PWD

python3 -m virtualenv .venv
. .venv/bin/activate


# Build fuzz introspector virtual environment and run OSS-Fuzz base image
# builder logic.
cd $ROOT_FI
python3 -m pip install -r ./requirements.txt
python3 -m pip install -r ./tools/web-fuzzing-introspection/requirements.txt
cd oss_fuzz_integration
./build_post_processing.sh

# Set up OSS-Fuzz-gen
cd $WORKDIR
git clone https://github.com/google/oss-fuzz-gen
cd oss-fuzz-gen
python3 -m pip install -r ./requirements.txt
