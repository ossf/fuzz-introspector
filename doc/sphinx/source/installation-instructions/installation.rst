Installation
============

Clone latest Fuzz Introspector and create virtual environment

.. code-block:: bash

    git clone --recurse-submodules https://github.com/ossf/fuzz-introspector
    cd fuzz-introspector
    python3 -m virtualenv .venv
    . .venv/bin/activate
    pip3 install -r requirements.txt

At this point you can test Fuzz Introspector with different frontends depending
on the type of language you want to analyse:

* :ref:`C/C++ <llvm_frontend>`
* :ref:`Python <python>`
* :ref:`Java <java>`


.. _llvm_frontend:

C/C++
.....

Fuzz-introspector relies on an LTO LLVM pass and this requires us to build a
custom Clang where the LTO pass is part of the compiler tool chain.
Additionally, we rely on the Gold linker, which means we need to build this too,
which comes as part of the binutils project. The next step is, therefore, to
do to this:

.. code-block:: bash

    mkdir build
    cd build

    # Build binutils
    apt install texinfo
    git clone --depth 1 git://sourceware.org/git/binutils-gdb.git binutils
    mkdir build
    cd ./build
    ../binutils/configure --enable-gold --enable-plugins --disable-werror
    make all-gold
    cd ../

    # Build LLVM and Clang
    git clone https://github.com/llvm/llvm-project/
    cd llvm-project/

    # Patch Clang to run fuzz introspector
    ../../frontends/llvm/patch_llvm.sh
    cp -rf ../../frontends/llvm/include/llvm/Transforms/FuzzIntrospector/ \
           ./llvm/include/llvm/Transforms/FuzzIntrospector
    cp -rf ../../frontends/llvm/lib/Transforms/FuzzIntrospector \
           ./llvm/lib/Transforms/FuzzIntrospector
    cd ../

    # Build LLVM and clang
    mkdir llvm-build
    cd llvm-build
    cmake -G "Unix Makefiles" -DLLVM_ENABLE_PROJECTS="clang;compiler-rt"  \
          -DLLVM_BINUTILS_INCDIR=../binutils/include \
          -DLLVM_TARGETS_TO_BUILD="X86" ../llvm-project/llvm/
    make llvm-headers
    make

We now have the LLVM frontend build and this will be used to extract data
about the software we analyse.

Option 1: only static analysis
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Build a test case

.. code-block:: bash

    # From the root of the fuzz-introspector repository
    cd tests/simple-example-0

    # Run compiler pass to generate *.data and *.data.yaml files
    mkdir work
    cd work
    FUZZ_INTROSPECTOR=1 ../../../build/llvm-build/bin/clang -fsanitize=fuzzer \
      -fuse-ld=gold -flto -g ../fuzzer.c -o fuzzer

    # Run post-processing to analyse data files and generate HTML report
    python3 ../../../src/main.py correlate --binaries_dir=.
    python3 ../../../src/main.py report \
      --target_dir=. \
      --correlation_file=./exe_to_fuzz_introspector_logs.yaml

    # The post-processing will have generated various .html, .js, .css and .png fies,
    # and these are accessible in the current folder. Simply start a webserver and 
    # navigate to the report in your local browser (localhost:8008):
    python3 -m http.server 8008

Option 2: include runtime code coverage
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
This is option 2.

.. code-block:: bash

    # From the root of the fuzz-introspector repository
    cd tests/simple-example-0

    # Run compiler pass to generate .data and .data.yaml files
    mkdir work
    cd work

    # Run script that will build fuzzer with coverage instrumentation and 
    # extract .profraw files
    # and convert those to .covreport files with "llvm-cov show"
    ../build_cov.sh

    # Build fuzz-introspector normally
    FUZZ_INTROSPECTOR=1 ../../../build/llvm-build/bin/clang -fsanitize=fuzzer \
      -fuse-ld=gold -flto -g ../fuzzer.c -o fuzzer

    # Run post-processing to analyse data files and generate HTML report
    python3 ../../../src/main.py correlate --binaries_dir=.
    python3 ../../../src/main.py report \
      --target_dir=. \
      --correlation_file=./exe_to_fuzz_introspector_logs.yaml

    # The post-processing will have generated various .html, .js, .css and .png fies,
    # and these are accessible in the current folder. Simply start a webserver and
    # navigate to the report in your local browser (localhost:8008):
    python3 -m http.server 8008


Python
......

The Python frontend uses the Abstract Syntax Tree to generate the data needed
by Fuzz Introspector. This is in contrast to the LLVM and Java frontends, which
both rely on compiled code. The benefit of this is that it is lighter from
a user perspective, however, the disadvantage is that there is less information
in the AST than in the compiled code.

The easiest way to get started with Fuzz Introspector for Python is to
build one of the test cases bundled in the Fuzz Introspector repository. We do
this using the following steps starting from the root of the Fuzz Introspector
repository:

.. code-block:: bash

   # Ensure that the Python frontend is in the PYTHONPATH
   cd frontends/python/PyCG
   export PYTHONPATH=$PWD
   cd ../../../

   # Build one of the Python examples
   cd tests/python/test4
   mkdir work
   cd work

   # Run the frontend on the code to extract data about the software package
   python3 ../../../../frontends/python/main.py \
       --fuzzer $PWD/../fuzz_test.py \
       --package=$PWD/../
   cd ..

   # Analyse the extract data and generate an HTML report
   mkdir web
   cd web
   python3 ../../../../src/main.py report \
     --target_dir=$PWD/../work \
     --language=python

   # Launch srver to view the generated HTML report
   python3 -m http.server 8008


Java
....

The Java frontend uses the `Soot framework <http://soot-oss.github.io/soot/>`_
for analysing and transforming Java class files (packed in JAR). The analysing
and transforming results are generated into data files needed by Fuzz Introspector.
This is similar to the LLVM frontends, which also rely on compiled code. As Java
contains many library classes included during compile time and run time, there
is additional logic in the Java frontend to ignore certain commonly known Java
library packages, like packages starting with ``java.`` or ``javax.``. This could
help reduce the processing time and resources needed for analysing and transforming
Java code.

The easiest way to get started with Fuzz Introspector for Java is to build one of
the test cases bundled in the Fuzz Introspector repository. We do this using the
following steps starting from the root of the Fuzz Introspector repository:

.. code-block:: bash

    # Build a set of Java examples
    # There are a total of 11 test cases named from test1 to test11
    # Built result are stored under ./result/testX where testX is the test case name
    cd tests/java
    mkdir -p result
    ./buildAll.sh

    # Run the frontend on the code to extract data about one of the Java examples
    cd ../../frontends/java
    ./run.sh -j ../../tests/java/test1/test1.jar -c TestFuzzer

    # Move the .data and .data.yaml generated by the frontend code to the result directory
    cd ../../tests/java
    mv ./fuzzer-*.data ./result/test1/
    mv ./fuzzer-*.data.yaml ./result/test1/

    # Analyse the extract data and generate an HTML report
    mkdir web
    cd web
    python3 ../../../src/main.py report \
      --target_dir=$PWD/../result/test1
      --language=jvm

    # Launch srver to view the generated HTML report
    python3 -m http.server 8008

The ``run.sh`` script in the second step is a wrapper to build the maven
project of the frontend code for Java project. It takes 2 mandatory parameters
and 4 optional parameters as shown as follows.

#. Mandatory parameters

   #. -j, --jarfile

      * Paths of all jar files of the project and its fuzzers and libraries, separated by ":".

   #. -c, --entryclass

      * List of fuzzers' entry classes, separated by ":".

#. Optional parameters

   #. -m, --entrymethod

      * List of fuzzers' entry methods within the entry classes, separated by ":".

      * Default value when this parameter is not provided: "fuzzerTestOneInput"

   #. -e, --excludeprefix

      * List of java package prefixes to be ignored by the frontend code, separated by ":".

      * Default value when this parameter is not provided: 
        ``"jdk.*:java.*:javax.*:sun.*:sunw.*:com.sun.*:com.ibm.*:com.apple.*:apple.awt.*: com.code_intelligence.jazzer.*"``

   #. -i, --includeprefix

      * List of java package prefixes that must be processed by the frontend code, even if it is excluded by the excludeprefix parameter above. Separated by ":".

      * Default value when this parameter is not provided:
        ``""``

   #. -s, --sinkmethod

      * List of java sink methods that needed to be handled by the frontend code, separated by ":".

      * Default value when this parameter is not provided: 
        ``"[java.lang.Runtime].exec:[javax.xml.xpath.XPath].compile:[javax.xml.xpath.XPath].evaluate:[java.lang.Thread].run:[java.lang.Runnable].run:[java.util.concurrent.Executor].execute:[java.util.concurrent.Callable].call:[java.lang.System].console:[java.lang.System].load:[java.lang.System].loadLibrary:[java.lang.System].apLibraryName:[java.lang.System].runFinalization:[java.lang.System].setErr:[java.lang.System].setIn:[java.lang.System].setOut:[java.lang.System].setProperties:[java.lang.System].setProperty:[java.lang.System].setSecurityManager:[java.lang.ProcessBuilder].directory:[java.lang.ProcessBuilder].inheritIO:[java.lang.ProcessBuilder].command:[java.lang.ProcessBuilder].redirectError:[java.lang.ProcessBuilder].redirectErrorStream:[java.lang.ProcessBuilder].redirectInput:[java.lang.ProcessBuilder].redirectOutput:[java.lang.ProcessBuilder].start"``
