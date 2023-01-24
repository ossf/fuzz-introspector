Identify and analyse fuzz blocker
---------------------------------

Fuzz Introspector provides certain features aimed at identifying any blockers
that fuzzers may run in to. In general terms, a fuzz blocker is something that
stops a fuzzer from exploring a certain part of the code. These blockers
can cause fuzzers to achieve sub-optimal code exploration and should be resolved
if possible. In this section we will discuss fuzz blockers and how Fuzz Introspector
can help find these blockers.


Identify blockers visually
~~~~~~~~~~~~~~~~~~~~~~~~~~

In order to capture fuzz blockers Fuzz Introspector fundamentally combines
the code coverage of a fuzzer at runtime with an approximation of the code
that a fuzzer should optimally explore. Identifying what a fuzzer should
optimally explore is a difficult task, and the goal of Fuzz Introspector is
not to get a perfect answer to this, but rather to provide something useful
and pragmatic for the fuzzer developer. Fuzz Introspector uses the
control-flow graph of a fuzzer as the definition of what it shuld optimally
achieve.

The simplest way Fuzz Introspector helps find fuzz blockers is by visualising
the calltree of a fuzzer, with coloring on each node the calltree indicating
if the node was hit at runtime or not.

For an example, consider the following calltree (taken from this `report <https://storage.googleapis.com/oss-fuzz-introspector/htslib/inspector-report/20230124/fuzz_report.html#call_tree_0>`_):

.. figure:: /user-guides/images/htslib-fuzzblocker.png
   :width: 800px
   :alt: Fuzz Blocker in htslib

The calltree is arrange such that the X-axis shows the callgraph of the fuzzer,
with the leftmost value being the entrypoint of the fuzzer and the rightmost
being the ending of the fuzzer. The nodes are created in a depth-first search
manner.

The coloring of the nodes have the following meaning:
- Red: the node was not covered at run time
- Yellow: the node was covered a few times at run time
- Green: the node was covered many times at run time

From the figure we extract the following conclusions:
- There is a large part of the fuzzer the fuzzer's calltree that has not been covered
- The nodes in the calltree at around 1100, 2100 and 4000 are the beginnings of large gaps

As such, the figure itself gives us a good quick understanding of the context.
The next steps is to understand the blockers further.


Inspect blockers at the calltree page
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Fuzz Introspector can tell us more about the blockers.


Inspect branch-level fuzz blockers
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Ultimately, the goal is often to get to the specific conditional in the code
that causes the blocking. Fuzz Introspector provides support for this.
