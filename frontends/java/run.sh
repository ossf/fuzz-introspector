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
    -i|--includeprefix)
      INCLUDEPREFIX="$2"
      shift
      shift
      ;;
    -x|--excludemethod)
      EXCLUDEMETHOD="$2"
      shift
      shift
      ;;
    -s|--sinkmethod)
      SINKMETHOD="$2"
      shift
      shift
      ;;
    -p|--package)
      PACKAGEPREFIX="$2"
      shift
      shift
      ;;
    -r|--src)
      SRCDIRECTORY="$2"
      shift
      shift
      ;;
    -a|--autofuzz)
      AUTOFUZZ="True"
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
if [ -z $EXCLUDEPREFIX ]
then
    echo "No exclude prefix list defined, using default exclude prefix list"
    EXCLUDEPREFIX="jdk.*:java.*:javax.*:sun.*:sunw.*:com.sun.*:com.ibm.*:com.apple.*:apple.awt.*:com.code_intelligence.jazzer.*"
fi
if [ -z $INCLUDEPREFIX ]
then
    echo "No include prefix list defined, using default include prefix list"
    INCLUDEPREFIX=
fi
if [ -z $EXCLUDEMETHOD ]
then
    echo "No exclude method list defined, using default exclude method list"
    EXCLUDEMETHOD="<clinit>:finalize:main"
fi
if [ -z $SINKMETHOD ]
then
    echo "No sink method list defined, using default sink method list"
    SINKMETHOD="[java.lang.Runtime].exec:[javax.xml.xpath.XPath].compile:[javax.xml.xpath.XPath].evaluate:[java.lang.Thread].run:[java.lang.Runnable].run:[java.util.concurrent.Executor].execute:[java.util.concurrent.Callable].call:[java.lang.System].console:[java.lang.System].load:[java.lang.System].loadLibrary:[java.lang.System].apLibraryName:[java.lang.System].runFinalization:[java.lang.System].setErr:[java.lang.System].setIn:[java.lang.System].setOut:[java.lang.System].setProperties:[java.lang.System].setProperty:[java.lang.System].setSecurityManager:[java.lang.ProcessBuilder].directory:[java.lang.ProcessBuilder].inheritIO:[java.lang.ProcessBuilder].command:[java.lang.ProcessBuilder].redirectError:[java.lang.ProcessBuilder].redirectErrorStream:[java.lang.ProcessBuilder].redirectInput:[java.lang.ProcessBuilder].redirectOutput:[java.lang.ProcessBuilder].start"
fi
if [ -z $PACKAGEPREFIX ]
then
    echo "No target package prefix defined, analysing all packages"
    PACKAGEPREFIX="ALL"
fi
if [ -z $SRCDIRECTORY ]
then
    SRCDIRECTORY="NULL"
fi
if [ -z $AUTOFUZZ ]
then
    AUTOFUZZ="False"
fi

# Build and execute the call graph generator
mvn clean package -Dmaven.test.skip

# Loop through all entry class
for CLASS in $(echo $ENTRYCLASS | tr ":" "\n")
do
    echo $CLASS
    java -Xmx6144M -cp "target/ossf.fuzz.introspector.soot-1.0.jar" ossf.fuzz.introspector.soot.CallGraphGenerator $JARFILE $CLASS $ENTRYMETHOD "$PACKAGEPREFIX" "$EXCLUDEMETHOD" "$SRCDIRECTORY" $AUTOFUZZ "$INCLUDEPREFIX===$EXCLUDEPREFIX===$SINKMETHOD"
done
