# Copyright 2021 Ada Logics Ltd.
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
  git checkout 7b1e0cbc8c280e37ddb87851b686df3bc8ae5c61
  git apply  --ignore-space-change --ignore-whitespace ../oss-fuzz-patches.diff
  echo "Done"
  cd ../
fi

rm -rf ./oss-fuzz/infra/base-images/base-clang/llvm
rm -rf ./oss-fuzz/infra/base-images/base-builder/post-processing

cp -rf ../llvm ./oss-fuzz/infra/base-images/base-clang/llvm
cp -rf ../post-processing ./oss-fuzz/infra/base-images/base-builder/post-processing

cd oss-fuzz
./infra/base-images/all.sh
