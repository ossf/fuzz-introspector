User guides
===========

This section presents various guides on how to use Fuzz Introspector. The
guides are rooted in real-world examples and real problems, and
the user guides focus on presenting fuzzing-relevant problems followed with
how Fuzz Introspector can be used to help.

This section can also be used as a general reference on various
approaches to fuzzing software, and if you have suggestions on heuristics
that would be nice to have support for in Fuzz Introspector, then we welcome
suggestions by way of Github: https://github.com/ossf/fuzz-introspector/issues

Many of the guides use real-world open source projects integrated into
OSS-Fuzz as reference examples. The guides do this either by referencing
a publicly available Fuzz Introspector report, or, by using the OSS-Fuzz
infrastructure to generate reports. This is for two reasons.
First, OSS-Fuzz has a myriad of important open source
projects that already use Fuzz Introspector, which provides a great data set.
Second, OSS-Fuzz has implemented an interface to Fuzz Introspector that is
straightforward to install and set up. For details on this, please see
:ref:`Running introspector on an OSS-Fuzz project`.

.. toctree::                                                                    
   :maxdepth: 3

   quick-overview
   analyse-fuzz-blocker
   get-ideas-for-new-targets
   comparing-introspector-reports
   control-instrumentation
   inspect-single-fuzzer
   identify-how-well-a-func-is-fuzzed
   analyse-sink-function
