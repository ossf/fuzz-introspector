#!/bin/bash -eu
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

if [ -d "oss-fuzz" ]
then
  echo "OSS-Fuzz directory exists. Reusing existing one"
else
  echo "Cloning oss-fuzz"
  git clone https://github.com/google/oss-fuzz
  echo "Applying diffs"
  cd oss-fuzz
  git apply  --ignore-space-change --ignore-whitespace ../oss-fuzz-patches.diff
  echo "Done"
  cd ../
fi

rm -rf ./oss-fuzz/infra/base-images/base-builder/post-processing/
rm -rf ./oss-fuzz/infra/base-images/base-builder/frontends
rm -rf ./oss-fuzz/infra/base-images/base-clang/fuzz-introspector/

mkdir ./oss-fuzz/infra/base-images/base-clang/fuzz-introspector/

cp -rf ../llvm ./oss-fuzz/infra/base-images/base-clang/fuzz-introspector/llvm
cp ../sed_cmds.sh ./oss-fuzz/infra/base-images/base-clang/fuzz-introspector/sed_cmds.sh
cp -rf ../post-processing ./oss-fuzz/infra/base-images/base-clang/fuzz-introspector/post-processing
cp -rf ../post-processing ./oss-fuzz/infra/base-images/base-builder/post-processing

cp -rf ../frontends ./oss-fuzz/infra/base-images/base-builder/frontends

# Skip all.sh if CLOUD_BUILD_ENV is set (it is in cloud build).
if [[ -z ${CLOUD_BUILD_ENV:+dummy} ]]; then
  echo 'running all.sh'
  cd oss-fuzz

  # Only build a subset of the oss-fuzz images because fuzz-introspector
  # only works with C/C++ projets.
  # Add an argument to avoid building with base-image and base-clang.
  if [[ $# -ne 1 ]]; then
    docker build --pull -t gcr.io/oss-fuzz-base/base-image infra/base-images/base-image
    docker build -t gcr.io/oss-fuzz-base/base-clang --build-arg introspector=local infra/base-images/base-clang
  fi
  docker build -t gcr.io/oss-fuzz-base/base-builder infra/base-images/base-builder
  docker build -t gcr.io/oss-fuzz-base/base-runner infra/base-images/base-runner
  docker build -t gcr.io/oss-fuzz-base/base-builder-python infra/base-images/base-builder-python

  #./infra/base-images/all.sh
fi
