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

# This script should be run from the fuzz-introspector/oss_fuzz_integration folder

# Copy over new post-processing
rm -rf ./oss-fuzz/infra/base-images/base-builder/post-processing
cp -rf ../post-processing ./oss-fuzz/infra/base-images/base-builder/post-processing
cd oss-fuzz
docker build -t gcr.io/oss-fuzz-base/base-builder "$@" infra/base-images/base-builder

# Sometimes you may want to rebuild base runner but only rarely.
# As such, one should provide an argument for that.
if [[ $# -eq 1 ]]; then
  docker build -t gcr.io/oss-fuzz-base/base-runner "$@" infra/base-images/base-runner
fi
