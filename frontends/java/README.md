# Java backend

This is work in progress.

Depends on OpenJDK+JRE 11.0 or later
Depends on https://github.com/gousiosg/java-callgraph, which has compiled and packed as a jar file (javacg-0.1-SNAPSHOT-static.jar)

It requires the target source code compiled and packed into jar file.

The resulting call tree are shown in stdout.

Example of running: `java -jar javacg-0.1-SNAPSHOT-static.jar <TARGET_JAR_FILE>`
