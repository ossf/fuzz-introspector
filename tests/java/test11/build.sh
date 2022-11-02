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
wget https://repo1.maven.org/maven2/javassist/javassist/3.12.1.GA/javassist-3.12.1.GA.jar
wget https://github.com/CodeIntelligenceTesting/jazzer/releases/download/v0.12.0/jazzer-linux-x86_64.tar.gz
tar -zxvf jazzer-linux-x86_64.tar.gz
javac -cp jazzer_api_deploy.jar:javassist-3.12.1.GA.jar ./*.java
unzip -uo javassist-3.12.1.GA.jar
jar cfv test11.jar ./*.class javassist
rm -rf ./jazzer*
rm -rf ./javassist*
rm -rf ./META-INF
