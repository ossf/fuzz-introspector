#!/bin/sh

rm -f ./*.class
rm -f ./*.jar
javac -cp ../jazzer_api_deploy.jar *.java
jar cfv test3.jar *.class
rm -f ./*.class
