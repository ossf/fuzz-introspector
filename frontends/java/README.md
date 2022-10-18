# Java backend

This is work in progress.

Download and install java / maven in ubuntu
-----------------------------------------
sudo apt-get install -y openjdk-8-jdk-headless maven


Using java-callgraph
-----------------------------------------
Depends on OpenJDK+JRE 8 or later

Depends on https://github.com/gousiosg/java-callgraph, which has compiled and packed as a jar file (javacg-0.1-SNAPSHOT-static.jar)

It requires the target source code compiled and packed into jar file.

The resulting call tree are shown in stdout.

Example of running: `java -jar javacg-0.1-SNAPSHOT-static.jar <TARGET_JAR_FILE>`


Using IBM's WALA
------------------------------------------
Depends on OpenJDK+JRE 8 or later

Depends on Maven 3.3 or later

Depends on IBM's WALA https://github.com/wala/WALA, the maven build process will automatically download and pack the WALA jar libraries.

The resulting call tree are shown in stdout.

Example of running: `./run.sh <-j | --jarFile> <jarFile1:...:javaFileN> <-e | --entryclass> <Public Entry Class Name>`


Using Soot
------------------------------------------
Depends on OpenJDK+JRE 8 or later

Depends on Maven 3.3 or later

Depends on IBM's WALA https://github.com/soot-oss/soot, the maven build process will automatically download and pack the Soot jar libraries.

The resulting call tree are shown in stdout.

Example of running: `./run.sh <-j | --jarFile> <jarFile1:...:javaFileN> <-c | --entryclass> <Public Entry Class Name> <-m | --entrymethod <Public Entry Method Name>`

