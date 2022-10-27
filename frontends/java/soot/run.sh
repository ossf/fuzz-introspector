#!/bin/bash

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
    java -Xmx6144M -cp "target/ossf.fuzz.introspector.soot-1.0.jar" ossf.fuzz.introspector.soot.CallGraphGenerator $JARFILE $CLASS $ENTRYMETHOD > $CLASS.result
done
