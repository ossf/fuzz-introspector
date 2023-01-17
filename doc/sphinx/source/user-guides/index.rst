User guides
===========

In this section we present various guides on how to use Fuzz Introspector. The
guides are rooted in real-world examples. The guides are meant for a reference
on how to use Fuzz Introspector to improve your fuzzing set up, but it can also
be used as a general reference on various approaches to fuzzing software.

Many of the guides will be using OSS-Fuzz projects as a reference example and
we will use the OSS-Fuzz infrastructure to carry out many examples.

This is for two reasons. First, OSS-Fuzz has a myriad of important open source
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

