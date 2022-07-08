#!/bin/bash -eu
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

if [ -d "oss-fuzz" ]
then
  echo "OSS-Fuzz directory exists. Reusing existing one"
else
  echo "Cloning oss-fuzz"
  git clone https://github.com/google/oss-fuzz
  echo "Done"
fi

echo 'Setting up docker images'

docker pull gcr.io/oss-fuzz-base/base-clang:introspector
docker pull gcr.io/oss-fuzz-base/base-builder:introspector
docker pull gcr.io/oss-fuzz-base/base-runner
docker tag gcr.io/oss-fuzz-base/base-builder:introspector gcr.io/oss-fuzz-base/base-builder:latest
docker tag gcr.io/oss-fuzz-base/base-clang:introspector gcr.io/oss-fuzz-base/base-clang:latest

