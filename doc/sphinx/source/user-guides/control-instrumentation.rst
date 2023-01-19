Focus analysis by controlling instrumentation
---------------------------------------------

This guide will go over how to focus analysis on specific code. This is used to
ensure the data that Fuzz Introspector handles is relevant to avoid bloating
the report with e.g. data about third-party dependencies.

The way both bug-sanitizers e.g. ASAN, code coverage visualization and Fuzz
Intropector work involves doing various efforts at compile time. We can focus
our analysis by only applying the logic on specific files. For example:

* Only code that we instrument with coverage visualisation will show up in the code coverage report.
* Only code that is instrumented with ASAN will have the necessary logic for detecting ASAN-reported bugs.
* Only code that is compiled with Fuzz Introspector enabled will be included in the Fuzz Introspector report.

.. note::

   How to instrument code is a wide topic, and can influence both performance
   and bug finding ability of a fuzzer. See e.g. https://blog.envoyproxy.io/a-stroll-down-fuzzer-optimisation-lane-and-why-instrumentation-policies-matter-f0012ec260b3
   for a deeper discussion on some of this.

The Fuzz Introspector reports depends on both the code that is analysed by the
Fuzz Introspector frontend and also the code coverage instrumentation as the code
coverage report is an input to Fuzz Introspector. In this guide, we will not
go into details with the internals of this, but rather show the difference
instrumentation policies matter on the output.

For this example we will use ``libarchive``. ``libarchive`` depends on ``libxml``.
``libxml`` is itself a large software package with tens of thousands of lines of
code. This example shows how instrumentation policies matter by first doing
a Fuzz Introspector with both ``libarchive`` and ``libxml`` beign instrumented
and included in the Fuzz Introspector analysis, and then doing a run with only
``libarchive`` compiled with the relevant instrumentation and ``libxml`` without
it. This example is based on the following PR that was made to perform this
exact change in https://github.com/google/oss-fuzz/pull/9007.

.. note::

   OSS-Fuzz sets environment variables when running ``build.sh``, which causes
   the necessary instrumentation to be applied during build. These environment
   variables are not set when the Docker image builds, i.e. building code in
   the ``Dockerfile`` in an OSS-Fuzz project means no instrumentation will be
   applied.

To show the difference between instrumenting/not instrumenting ``libxml`` we
will first run a Fuzz Introspector run of the OSS-Fuzz set up of ``libarchive``
with the build instructions for ``libxml`` inside of the ``build.sh`` file. This
corresponds to the state of the ``libarchive`` project as it was *before*
the changes in https://github.com/google/oss-fuzz/pull/9007/files was merged
into OSS-Fuzz:

.. code-block:: bash

   # Clone a clean version of oss-fuzz
   git clone https://github.com/google/oss-fuzz
   cd oss-fuzz

   # At this point you need to:
   # Revert the changes in the mentioned PR, so the instructions for building
   # libxml is in projects/libarchive/build.sh and not in projects/libarchive/Dockerfile
   # In other words, revert https://github.com/google/oss-fuzz/pull/9007
   # Do this revert manually, as other things my have changed in the set up.

   # Modify the libarchive build.sh to *not* have the lines:
   # https://github.com/google/oss-fuzz/blob/65d4864780850058107f25d529710e84d2365acd/projects/libarchive/build.sh#L18-L24

   # Generate an introspector report
   python3 infra/helper.py introspector libarchive --seconds=10

   # Save the introspector report to a path outside `build` so we have it
   # for comparison purposes later.
   cp -rf build/out/libarchive/introspector-report/ introspector-report-1

At this point we will revert the changes done in libarchive, which we can
achieve with ``git stash``. After the git stash, we can clean up the ``build``
and do the exact same steps as above. As such, we do the following steps:

.. code-block:: bash

   # Clean up build
   sudo rm -rf ./build

   # Undo the changes to the ``libarchive`` set up.
   git stash

   # Modify the libarchive build.sh to *not* have the lines:
   # https://github.com/google/oss-fuzz/blob/65d4864780850058107f25d529710e84d2365acd/projects/libarchive/build.sh#L18-L24

   # Generate an introspector report
   python3 infra/helper.py introspector libarchive --seconds=10

   # Save the introspector report to a path outside `build`.
   cp -rf build/out/libarchive/introspector-report/ introspector-report-2

At this stage we have two different introspector reports: ``introspector-report-1``
which holds the project with ``libxml`` included in the analysis, and ``introspector-report-2``
which holds the project with ``libxml`` excluded from the analysis. We will
now start two web servers and so we can observe the differences in the reports.

The differences between the reports are visible. For example,
the total number of functions and cyclomatic complexity changes between the
two instances of the project. This is shown by the following two figures.

``libarchive`` overview stats with ``libxml`` included in the analysis:

.. figure:: /user-guides/images/libarchive-with-lxml-overview.png
   :width: 800px
   :alt: libarchive overview with libxml

|

``libarchive`` overview stats with ``libxml`` excluded in the analysis:

.. figure:: /user-guides/images/libarchive-without-lxml-overview.png
   :width: 800px
   :alt: libarchive overview without libxml

|


The difference is also visible elsewhere, for example the project functions
overview table.
The following figure shows ``libarchive`` function overview with ``libxml``
included in the analysis. Notice the search box queries for ``libxml`` to
display the number of ``libxml`` functions, totalling to 2607 entries:


.. figure:: /user-guides/images/libarchive-with-lxml-func-overview.png
   :width: 800px
   :alt: libarchive function overview with libxml

|

``libarchive`` function overview stats without ``libxml`` included in analysis.
Notice the same query as above is in the search box, but there are no entries
that matches the query:

.. figure:: /user-guides/images/libarchive-without-lxml-func-overview.png
   :width: 800px
   :alt: libarchive function overview without libxml
