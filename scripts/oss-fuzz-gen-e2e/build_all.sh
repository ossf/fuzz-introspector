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

mkdir workdir
cd workdir
BASE=$PWD

python3.11 -m virtualenv .venv
. .venv/bin/activate


# FI
git clone https://github.com/ossf/fuzz-introspector
cd fuzz-introspector
python3 -m pip install -r ./requirements.txt

cd oss_fuzz_integration
./build_post_processing.sh

# OSS-Fuzz-gen
cd $BASE
git clone https://github.com/google/oss-fuzz-gen
cd oss-fuzz-gen
python3 -m pip install -r ./requirements.txt
