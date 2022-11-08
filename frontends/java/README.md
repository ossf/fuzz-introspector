# Java backend

This is work in progress.

Download and install java / maven in ubuntu
-----------------------------------------
`sudo apt-get install -y openjdk-8-jdk-headless maven`
or 
`sudo apt-get install -y openjdk-11-jdk-headless maven`
depends on the application you want to run. 

java-callgraph and soot approach could run with OpenJDK+JRE 8 or later, while WALA can only run with OpenJDK+JRE 11 or later.


Prepare your java application for the static analysis
-----------------------------------------
You need to pack your java application (your compiled java bytecode in *.class to jar files in order to use the static analysis.

After you have compiled your *.java source code into *.class bytecode. You could use the following commands to pack them into a jar file

Command: `jar cvf <name of jar file> <all you class file>`

The sample command below will generate an app.jar file which contains main.class sub1.class and sub.class

Sample command: `jar cvf app.jar main.class sub1.class sub2.class`


Sample application for testing
-----------------------------------------
In fuzz-introspector/tests/java directory, there are 7 sample testcases. Each of them contains a sample java application and a build script.

Just go into one of the testcases directories (test1 to test7) and execute the build script, it will automatically generate a jar file (2 jar files for test7) for testing in the same directory

You could also run build all script at fuzz-introspector/tests/java directory and it will automatically build all the testcases and store all resulting jar in the test-jar directory.

You could then use the generated file for the static analysis by specifying its full path or move it to the necessary locations.

The compiling of all those testcases required the Jazzer-API library. The build script of each testcases will automatically pull version 0.12.0 of the jazzer-API.jar from their official release page. If you want to build your own jazzer jar file, please refer to their own documentation at https://github.com/CodeIntelligenceTesting/jazzer/blob/main/README.md#getting-jazzer

Example for compiling and packing jar file for testcase test1: `cd path/to/fuzz-introspector/tests/java/test1; ./build.sh`

Example for compiling and packing jar file for all testcase: `cd path/to/fuzz-introspector/tests/java/; ./buildAll.sh`


Using java-callgraph
-----------------------------------------
Depends on OpenJDK+JRE 8 or later

Depends on https://github.com/gousiosg/java-callgraph, which has compiled and packed as a jar file (javacg-0.1-SNAPSHOT-static.jar)

To compile your own javacg-0.1-SNAPSHOT-static.jar, follows the steps below.

```
 git clone https://github.com/gousiosg/java-callgraph 
 cd java-callgraph
 mvn install
```

After compiling the java-callgraph, the needed javacg-0.1-SNAPSHOT-static.jar is in the target directory.

The resulting call tree are shown in stdout.

Command:
```
  cd frontends/java/java-callgraph
  java -jar javacg-0.1-SNAPSHOT-static.jar <TARGET_JAR_FILE>
```

Example for execution using testcase test1:
```
  cd frontends/java/java-callgraph
  java -jar javacg-0.1-SNAPSHOT-static.jar path/to/fuzz-introspector/tests/java/test1/test1.jar
```

Example for execution using testcase test5:
```
  cd frontends/java/java-callgraph
  java -jar javacg-0.1-SNAPSHOT-static.jar path/to/fuzz-introspector/tests/java/test5/test5.jar
```


Using IBM's WALA
------------------------------------------
Depends on OpenJDK+JRE 11 or later

Depends on Maven 3.3 or later

Depends on IBM's WALA https://github.com/wala/WALA, the maven build process will automatically download and pack the WALA jar libraries.

The resulting call tree are shown in stdout.

**Current limitation, the entryclass must contains the main method to build the callgraph.**

Example of running: 
```
  cd frontends/java/wala
  ./run.sh <-j | --jarfile> <jarFile1:...:javaFileN> <-c | --entryclass> <Public Entry Class Name>
```

Example for execution using testcase test1:
```
  cd frontends/java/wala
  ./run.sh --jarfile path/to/fuzz-introspector/tests/java/test1/test1.jar --entryclass TestFuzzer
```

Example for execution using testcase test5:
```
  cd frontends/java/wala
  ./run.sh --jarfile path/to/fuzz-introspector/tests/java/test5/test5.jar --entryclass Fuzz.TestFuzzer`
```

Using Soot
------------------------------------------
Depends on OpenJDK+JRE 8 or later 

Depends on Maven 3.3 or later

Depends on Soot https://github.com/soot-oss/soot, the maven build process will automatically download and pack the Soot jar libraries.

The resulting call tree and extra parameter are stored in <ENTRY_CLASS>.result 

Example of running: 

```
  cd frontends/java/soot
  ./run.sh <-j | --jarfile> <jarFile1:...:javaFileN> <-c | --entryclass> <Public Entry Class Name 1:...:Public Entry Class Name N> [-m | --entrymethod <Public Entry Method Name>]
```

**__If --entrymethod is ommited, the default value 'fuzzerTestOneInput' will be used.__**
**__Multiple jar file or entry class is allowed, values should be separated with ':'.__**
**__Necessary jar library could be added to the --jarfile options__.**
**__If there is multiple match of entry classes, only the first found will be handled.__**


Example for execution using testcase test1:
```
  cd path/to/fuzz-introspector/frontends/java/soot
  ./run.sh -j path/to/fuzz-introspector/tests/java/test-jar/test1.jar -c TestFuzzer -m fuzzerTestOneInput
  # To view result
  cat fuzzerLogFile-TestFuzzer.data
  cat fuzzerLogFile-TestFuzzer-*.data.yaml
```

Example for execution using testcase test5: 
```
  cd path/to/fuzz-introspector/frontends/java/soot
  ./run.sh -j path/to/fuzz-introspector/tests/java/test-jar/test5.jar -c Fuzz.TestFuzzer -m fuzzerTestOneInput
  # To view result
  cat fuzzerLogFile-Fuzz.TestFuzzer.data
  cat fuzzerLogFile-Fuzz.TestFuzzer-*.data.yaml
```

Example for execution using testcase test6 (with multiple entry classes in same jar file): 
```
  cd path/to/fuzz-introspector/frontends/java/soot
  ./run.sh -j path/to/fuzz-introspector/tests/java/test-jar/test6.jar -c Fuzz.TestFuzzer:Fuzz.TestFuzzer2 -m fuzzerTestOneInput
  # To view result
  cat fuzzerLogFile-Fuzz.TestFuzzer.data
  cat fuzzerLogFile-Fuzz.TestFuzzer-*.data.yaml
  cat fuzzerLogFile-Fuzz.TestFuzzer2.data
  cat fuzzerLogFile-Fuzz.TestFuzzer2-*.data.yaml
```

Example for execution using testcase test7 (with multiple entry classes in multiple jar files): 
```
  cd path/to/fuzz-introspector/frontends/java/soot
  ./run.sh -j path/to/fuzz-introspector/tests/java/test-jar/test7-1.jar:path/to/fuzz-introspector/tests/java/test-jar/test7-2.jar -c Fuzz.TestFuzzer:Fuzz2.TestFuzzer2 -m fuzzerTestOneInput
  # To view result
  cat fuzzerLogFile-Fuzz.TestFuzzer.data
  cat fuzzerLogFile-Fuzz.TestFuzzer-*.data.yaml
  cat fuzzerLogFile-Fuzz2.TestFuzzer2.data
  cat fuzzerLogFile-Fuzz2.TestFuzzer2-*.data.yaml
```


Sample output for testcase test1
------------------------------------------
**java-callgraph**
```
C:TestFuzzer com.code_intelligence.jazzer.api.CannedFuzzedDataProvider
C:TestFuzzer TestFuzzer
C:TestFuzzer java.lang.Object
C:TestFuzzer java.lang.System
C:TestFuzzer java.io.PrintStream
M:TestFuzzer:<init>() (O)java.lang.Object:<init>()
M:TestFuzzer:fuzzerTestOneInput(com.code_intelligence.jazzer.api.FuzzedDataProvider) (M)java.io.PrintStream:println(java.lang.String)
M:TestFuzzer:main(java.lang.String[]) (O)com.code_intelligence.jazzer.api.CannedFuzzedDataProvider:<init>(java.lang.String)
M:TestFuzzer:main(java.lang.String[]) (S)TestFuzzer:fuzzerTestOneInput(com.code_intelligence.jazzer.api.FuzzedDataProvider)
```

**Wala**
```
Node: synthetic < Primordial, Lcom/ibm/wala/FakeRootClass, fakeRootMethod()V > Context: Everywhere
 - invokestatic < Primordial, Lcom/ibm/wala/FakeRootClass, fakeWorldClinit()V >@0
   -> Node: synthetic < Primordial, Lcom/ibm/wala/FakeRootClass, fakeWorldClinit()V > Context: Everywhere
 - invokespecial < Primordial, Ljava/lang/Object, <init>()V >@4
   -> Node: < Primordial, Ljava/lang/Object, <init>()V > Context: Everywhere
 - invokestatic < Application, LTestFuzzer, main([Ljava/lang/String;)V >@5
   -> Node: < Application, LTestFuzzer, main([Ljava/lang/String;)V > Context: Everywhere
Node: synthetic < Primordial, Lcom/ibm/wala/FakeRootClass, fakeWorldClinit()V > Context: Everywhere
 - invokestatic < Primordial, Ljava/lang/Object, <clinit>()V >@0
   -> Node: < Primordial, Ljava/lang/Object, <clinit>()V > Context: Everywhere
 - invokestatic < Primordial, Ljava/lang/String, <clinit>()V >@1
   -> Node: < Primordial, Ljava/lang/String, <clinit>()V > Context: Everywhere
Node: < Primordial, Ljava/lang/Object, <clinit>()V > Context: Everywhere
 - invokestatic < Primordial, Ljava/lang/Object, registerNatives()V >@0
   -> Node: < Primordial, Ljava/lang/Object, registerNatives()V > Context: Everywhere
Node: < Primordial, Ljava/lang/Object, registerNatives()V > Context: Everywhere
Node: < Primordial, Ljava/lang/String, <clinit>()V > Context: Everywhere
 - invokespecial < Primordial, Ljava/lang/String$CaseInsensitiveComparator, <init>(Ljava/lang/String$1;)V >@12
   -> Node: < Primordial, Ljava/lang/String$CaseInsensitiveComparator, <init>(Ljava/lang/String$1;)V > Context: Everywhere
Node: < Primordial, Ljava/lang/String$CaseInsensitiveComparator, <init>(Ljava/lang/String$1;)V > Context: Everywhere
 - invokespecial < Primordial, Ljava/lang/String$CaseInsensitiveComparator, <init>()V >@1
   -> Node: < Primordial, Ljava/lang/String$CaseInsensitiveComparator, <init>()V > Context: Everywhere
Node: < Primordial, Ljava/lang/String$CaseInsensitiveComparator, <init>()V > Context: Everywhere
 - invokespecial < Primordial, Ljava/lang/Object, <init>()V >@1
   -> Node: < Primordial, Ljava/lang/Object, <init>()V > Context: Everywhere
Node: < Primordial, Ljava/lang/Object, <init>()V > Context: Everywhere
Node: < Application, LTestFuzzer, main([Ljava/lang/String;)V > Context: Everywhere
 - invokestatic < Application, LTestFuzzer, fuzzerTestOneInput(Lcom/code_intelligence/jazzer/api/FuzzedDataProvider;)V >@9
   -> Node: < Application, LTestFuzzer, fuzzerTestOneInput(Lcom/code_intelligence/jazzer/api/FuzzedDataProvider;)V > Context: Everywhere
Node: < Application, LTestFuzzer, fuzzerTestOneInput(Lcom/code_intelligence/jazzer/api/FuzzedDataProvider;)V > Context: Everywhere
```

**Soot**
fuzzerLogFile-XXX.data
```
Call Tree
fuzzerTestOneInput linenumber=-1
 println java.io.PrintStream linenumber=21
```
fuzzerLogFile-XXX-YYY.data.yaml
```
```
