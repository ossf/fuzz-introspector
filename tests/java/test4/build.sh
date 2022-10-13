#!/bin/sh

rm -f ./Fuzz/*.class
rm -f ./*.jar
javac -cp ../jazzer_api_deploy.jar ./Fuzz/*.java
jar cfv test4.jar ./Fuzz/*.class
