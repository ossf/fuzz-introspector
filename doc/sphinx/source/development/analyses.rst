Fuzz Introspector analyses
--------------------------

Fuzz Introspector is architected to support plugin-style development
of analysis tooling. This makes it possible to construct tooling that
uses Fuzz Introspector's core functionality and extends it for specific
applications.

This page contains details about the current analysis plugins.

All plugins are located in `src/fuzz-introspector/analyses <https://github.com/ossf/fuzz-introspector/tree/main/src/fuzz_introspector/analyses>`_

Optimal targets
===============
.. automodule:: fuzz_introspector.analyses.optimal_targets
   :members:
   :show-inheritance:

Runtime coverage analysis
=========================
.. automodule:: fuzz_introspector.analyses.runtime_coverage_analysis
   :members:
   :show-inheritance:

Calltree analysis
=================
.. automodule:: fuzz_introspector.analyses.calltree_analysis
   :members:
   :show-inheritance:

Driver synthesizer
==================
.. automodule:: fuzz_introspector.analyses.driver_synthesizer
   :members:
   :show-inheritance:

Filepath analyser
=================
.. automodule:: fuzz_introspector.analyses.filepath_analyser
   :members:
   :show-inheritance:

Engine input
============
.. automodule:: fuzz_introspector.analyses.engine_input
   :members:
   :show-inheritance:

Sink function analyser
======================
.. automodule:: fuzz_introspector.analyses.sinks_analyser
   :members:
   :show-inheritance:
