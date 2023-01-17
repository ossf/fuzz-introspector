User guides
===========

This section presents various guides on how to use Fuzz Introspector. The
guides are rooted in real-world example and real problems, in the sense that
the user guides try to focus on presenting a fuzzing-relevant problem and then
outline how Fuzz Introspector can help.

This section can also be used as a general reference on various
approaches to fuzzing software, and if you have suggestions on heuristics
that would be nice to have support for in Fuzz Introspector, then we welcome
suggestions by way of Github: https://github.com/ossf/fuzz-introspector/issues

Many of the guides will be using OSS-Fuzz projects as a reference example and
we will use the OSS-Fuzz infrastructure to carry out many examples. This is for two reasons.
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

