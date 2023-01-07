..

OSS-Fuzz guides
===============

In this section we will go through how to use Fuzz Introspector with OSS-Fuzz.
Fuzz Introspector is integrated into
`OSS-Fuzz <https://github.com/google/oss-fuzz>`_. This means that the OSS-Fuzz
infrastructure provides a set of features for running Introspector on an
arbitrary OSS-Fuzz project. The goal of this is to make it easier for
maintainers of projects on OSS-Fuzz to assess the completeness of their fuzzing
setup.

Running introspector on an OSS-Fuzz project
-------------------------------------------

Running Fuzz Introspector by way of OSS-Fuzz is beneficial in that OSS-Fuzz
abstracts away many of the tasks needed, e.g. generating corpus, generating
coverage, compiling fuzzers in various ways and finally running Fuzz
Introspector on the generated data. In fact, using the OSS-Fuzz environment
makes it possible to run Fuzz Introspector with a single command, as shown
in the following example:

.. code-block:: bash

   # Clone oss-fuzz
   git clone https://github.com/google/oss-fuzz
   cd oss-fuzz

   # Build a project using introspector
   python3 infra/helper.py introspector libdwarf --seconds=30

In the event of success, the last ouput you see should be something along
the lines of:

.. code-block:: bash

   INFO:root:Introspector run complete. Report in /home/dav/code/oss-fuzz/build/out/libdwarf/introspector-report/inspector
   INFO:root:To browse the report, run: python3 -m http.server 8008 --directory /home/dav/code/oss-fuzz/build/out/libdwarf/introspector-report/inspector and navigate to localhost:8008/fuzz_report.html in your browser


You can then launch a simple web server following the description:

.. code-block:: bash

   # View the generate HTML report
   python3 -m http.server 8008 \
     --directory build/out/libdwarf/introspector-report/inspector

   # Navigate to https://localhost:8008/fuzz_report.html to view the report.


Generate Fuzz Introspector report with latest public corpus
-----------------------------------------------------------

Runtime code coverage is a central theme in Fuzz Introspector. It helps us
understand the actual code executed by our fuzzers, and is a core part of
ensuring the fuzzers analyse the code we want them to analyse.

OSS-Fuzz builds up a corpus of test case inputs over time for each fuzzer.
A 30-day old version of this corpus is publicly available. We can use this
corpus to generate an almost-up-to-date understanding of how much of the code
OSS-Fuzz has analysed.

To use the latest corpus, we just need to `--public-corpora` to the
`introspector` command. The following example shows how to do this:

.. code-block:: bash

   # Clone oss-fuzz
   git clone https://github.com/google/oss-fuzz
   cd oss-fuzz

   # Build a project using introspector
   python3 infra/helper.py introspector libdwarf --public-corpora

