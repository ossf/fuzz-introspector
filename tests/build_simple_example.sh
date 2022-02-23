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
export FUZZ_INTROSPECTOR=1
for PROJ in simple-example-0; do
  cd ${ROOT}/${PROJ}
  rm -rf ./web

  ./build_all.sh
  python3 ${ROOT}/../post-processing/main.py correlate --binaries_dir=./work/
  #exit 0
  ./build_cov.sh || true
  mkdir web
  cd web
  python3 ${ROOT}/../post-processing/main.py report --correlation_file=../exe_to_fuzz_introspector_logs.yaml --target_dir=../
done
