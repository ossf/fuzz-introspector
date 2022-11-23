# Java backend

This is work in progress.

Download and install java / maven in ubuntu
-----------------------------------------
`sudo apt-get install -y openjdk-8-jdk-headless maven`
or 
`sudo apt-get install -y openjdk-11-jdk-headless maven`
depends on the application you want to run. 

java-callgraph and soot approach could run with OpenJDK+JRE 8 or later, while WALA can only run with OpenJDK+JRE 11 or later.


Java Code Formatting Standard
-----------------------------------------
Google Java Format is being adopted to Fuzz-Introspector repository. Every new commit of java file will be checked and verified that it follows the formatting standard.

Official guidelines for the required formatting can be found in [https://google.github.io/styleguide/javaguide.html](https://google.github.io/styleguide/javaguide.html)

You can use the official tools locally to check and fix your coding to make it follows the standing. See the link [https://github.com/google/google-java-format](https://github.com/google/google-java-format) for downloading, installing and applying the tools locally.

If your commited code fail to pass the CI checking, a diff of suggested changes are provided and you could use either `git apply` or the official `google-java-format-diff.py` tool. Remember to double check the correctness of the diff before applying to your code.

Prepare your java application for the static analysis
-----------------------------------------
You need to pack your java application (your compiled java bytecode in *.class to jar files in order to use the static analysis.

After you have compiled your *.java source code into *.class bytecode. You could use the following commands to pack them into a jar file

Command: `jar cvf <name of jar file> <all you class file>`

The sample command below will generate an app.jar file which contains main.class sub1.class and sub.class

Sample command: `jar cvf app.jar main.class sub1.class sub2.class`


Sample application for testing
-----------------------------------------
In fuzz-introspector/tests/java directory, there are 14 sample testcases. Each of them contains a sample java application and a build script.

Just go into one of the testcases directories (test1 to test14) and execute the build script, it will automatically generate one or more jar files for testing in the same directory

You could also run build all script at fuzz-introspector/tests/java directory and it will automatically build all the testcases and store all resulting jar in the test-jar directory.

You could then use the generated file for the static analysis by specifying its full path or move it to the necessary locations.

The compiling of all those testcases required the Jazzer-API library. The build script of each testcases will automatically pull version 0.12.0 of the jazzer-API.jar from their official release page. If you want to build your own jazzer jar file, please refer to their own documentation at https://github.com/CodeIntelligenceTesting/jazzer/blob/main/README.md#getting-jazzer

Example for compiling and packing jar file for testcase test1: `cd path/to/fuzz-introspector/tests/java/test1; ./build.sh`

Example for compiling and packing jar file for all testcase: `cd path/to/fuzz-introspector/tests/java/; ./buildAll.sh`


Using Soot
------------------------------------------
Depends on OpenJDK+JRE 8 or later 

Depends on Maven 3.3 or later

Depends on Soot https://github.com/soot-oss/soot, the maven build process will automatically download and pack the Soot jar libraries.

The resulting call tree and extra parameter are stored in <ENTRY_CLASS>.result 

Example of running: 

```
  cd frontends/java/soot
  ./run.sh <-j | --jarfile> <jarFile1:...:javaFileN> <-c | --entryclass> <Public Entry Class Name 1:...:Public Entry Class Name N> [-m | --entrymethod <Public Entry Method Name>] [-e | --excludeprefix <Excluded package prefix>]
```

**__If --entrymethod is ommited, the default value 'fuzzerTestOneInput' will be used.__**

**__Multiple jar files, entry classes and exclude prfixes are allowed, values should be separated with ':'.__**

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

Two output files provided for each Fuzzer Class
```
  fuzzerLogFile-<Fuzzer Class>.data
  fuzzerLogFile-<Fuzzer Class>.data.yaml
```

_fuzzerFile-<Fuzzer Class>.data_ stores the call graph generation, following the format mentioned in [https://github.com/ossf/fuzz-introspector/blob/main/doc/LanguageImplementation.md#calltree-data-structure](https://github.com/ossf/fuzz-introspector/blob/main/doc/LanguageImplementation.md#calltree-data-structure)

_fuzzerFile-<Fuzzer Class>.data.yaml_ stores other program-wide data, following the format mentioend in [https://github.com/ossf/fuzz-introspector/blob/main/doc/LanguageImplementation.md#program-wide-data-file](https://github.com/ossf/fuzz-introspector/blob/main/doc/LanguageImplementation.md#program-wide-data-file)

