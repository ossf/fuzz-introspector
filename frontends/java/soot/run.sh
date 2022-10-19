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
    echo "You need to specify target with -j <jar_file> or --jarfile <jar_file>."
    exit 1
fi
if [ -z $ENTRYCLASS ]
then
    echo "You need to specify entry class with -c <entry_class> or --entryclass <entry_class>."
    exit 1
fi
if [ -z $ENTRYMETHOD ]
then
    echo "You need to specify entry class with -m <entry_method> or --entrymethod <entry_method>."
    exit 1
fi

# Build and execute the call graph generator
mvn clean package
java -Xmx6144M -cp "target/ossf.fuzz.introspector.soot-1.0.jar" ossf.fuzz.introspector.soot.CallGraphGenerator $JARFILE $ENTRYCLASS $ENTRYMETHOD
