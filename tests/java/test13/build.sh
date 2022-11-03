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
wget https://repo1.maven.org/maven2/org/eclipse/angus/angus-mail/1.0.0/angus-mail-1.0.0.jar
wget https://github.com/CodeIntelligenceTesting/jazzer/releases/download/v0.12.0/jazzer-linux-x86_64.tar.gz
tar -zxvf jazzer-linux-x86_64.tar.gz
unzip -uo angus-mail-1.0.0.jar
rm *.class
javac -cp jazzer_api_deploy.jar:angus-mail-1.0.0.jar ./*.java
jar cfv test13.jar ./*.class com
rm -rf ./jazzer*
rm -rf ./com*
rm -rf ./META-INF
