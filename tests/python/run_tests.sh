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

# Ensure https://github.com/AdaLogics/PyCG is in your PYTHONPATH

ROOT=$PWD
export PYTHONPATH=$ROOT/../../frontends/python/PyCG/
for PROJ in test1 test2 test3 test4; do
  cd $ROOT/$PROJ
  rm -rf ./work
  mkdir work
  cd work

  # Extract data
  python3 $ROOT/../../frontends/python/main.py --fuzzer $PWD/../fuzz_test.py --package=$PWD/../
  cd ../

  # Run post-processing
  rm -rf ./web
  mkdir web
  cd web
  python3 $ROOT/../../post-processing/main.py report --target_dir=$PWD/../work/

done
