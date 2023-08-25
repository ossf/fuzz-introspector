#!/bin/sh
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

rm -f ./*.class
rm -f ./*.jar
rm -f ./jazzer*
wget https://repo1.maven.org/maven2/com/code-intelligence/jazzer-api/0.19.0/jazzer-api-0.19.0.jar
wget https://repo1.maven.org/maven2/com/code-intelligence/jazzer-junit/0.19.0/jazzer-junit-0.19.0.jar
javac -cp jazzer-api-0.19.0.jar:jazzer-junit-0.19.0.jar *.java
jar cfv test12.jar *.class
rm -rf ./jazzer*
