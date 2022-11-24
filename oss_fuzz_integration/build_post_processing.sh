#!/bin/bash -eux
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

  echo "Downloading base-image and base-clang OSS-Fuzz introspector builds"
  docker pull gcr.io/oss-fuzz-base/base-clang:introspector
  docker tag gcr.io/oss-fuzz-base/base-clang:introspector gcr.io/oss-fuzz-base/base-clang:latest
fi

echo "Building base-build, base-builder-python and base-runner for fuzz introspector"
# This script should be run from the fuzz-introspector/oss_fuzz_integration folder
# Copy over new post-processing
rm -rf ./oss-fuzz/infra/base-images/base-builder/src
cp -rf ../src ./oss-fuzz/infra/base-images/base-builder/src

rm -rf ./oss-fuzz/infra/base-images/base-builder/frontends
cp -rf ../frontends/ ./oss-fuzz/infra/base-images/base-builder/frontends

cd oss-fuzz
docker build -t gcr.io/oss-fuzz-base/base-builder infra/base-images/base-builder
docker build -t gcr.io/oss-fuzz-base/base-builder-python infra/base-images/base-builder-python
docker build -t gcr.io/oss-fuzz-base/base-builder-jvm infra/base-images/base-builder-jvm
docker build -t gcr.io/oss-fuzz-base/base-runner infra/base-images/base-runner
