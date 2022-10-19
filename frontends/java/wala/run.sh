#!/bin/bash

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

mvn clean package
java -jar target/ossf.fuzz.introspector.wala-1.0.jar -jarFile $JARFILE -entryClass $ENTRYCLASS
