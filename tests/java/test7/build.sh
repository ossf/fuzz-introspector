#!/bin/sh

rm -f ./*/*.class
rm -f ./*.jar
rm -f ./jazzer*
wget https://github.com/CodeIntelligenceTesting/jazzer/releases/download/v0.12.0/jazzer-linux-x86_64.tar.gz
tar -zxvf jazzer-linux-x86_64.tar.gz
javac -cp jazzer_api_deploy.jar ./*/*.java
jar cfv test7-1.jar ./Fuzz/*.class ./Function/*.class
jar cfv test7-2.jar ./Fuzz2/*.class
rm -rf ./jazzer*
