#!/bin/bash
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

# Process arguments
JARFILE=
ENTRYCLASS=

while [[ $# -gt 0 ]]; do
  case $1 in
    -j|--jarfile)
      JARFILE="$2"
      shift
      shift
      ;;
    -c|--entryclass)
      ENTRYCLASS="$2"
      shift
      shift
      ;;
    -m|--entrymethod)
      ENTRYMETHOD="$2"
      shift
      shift
      ;;
    -e|--excludeprefix)
      EXCLUDEPREFIX="$2"
      shift
      shift
      ;;
    *)
      echo "Unknown option $1"
      exit 1
      ;;
  esac
done

if [ -z $JARFILE ]
then
    echo "You need to specify target with -j <jar_files> or --jarfile <jar_files>. Multiple jar file should be separated with colon ':'."
    exit 1
fi
if [ -z $ENTRYCLASS ]
then
    echo "You need to specify entry classes name with -c <entry_classes> or --entryclass <entry_classes>. Multiple entry class should be separated with colon ':'."
    exit 1
fi
if [ -z $ENTRYMETHOD ]
then
    echo "No entry method defined, using default entry method 'fuzzerTestOneInput'"
    ENTRYMETHOD="fuzzerTestOneInput"
fi

# Build and execute the call graph generator
mvn clean package

# Loop through all entry class
for CLASS in $(echo $ENTRYCLASS | tr ":" "\n")
do
    echo $CLASS
    java -Xmx6144M -cp "target/ossf.fuzz.introspector.soot-1.0.jar" ossf.fuzz.introspector.soot.CallGraphGenerator $JARFILE $CLASS $ENTRYMETHOD $EXCLUDEPREFIX > $CLASS.result
done
