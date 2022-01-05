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

#for PROJ in simple-example-0 simple-example-1 simple-example-2 simple-example-3 simple-example-4 simple-example-indirect-pointers; do
#for PROJ in cpp-simple-example-1; do
for PROJ in simple-example-0; do
  cd ${ROOT}/${PROJ}
  rm -rf ./web

  ./build_all.sh
  mkdir web
  cd web
  python3 ${ROOT}/../post-processing/main.py --target_dir=../
done
