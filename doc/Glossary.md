# Glossary

This document provides definitions of concepts in fuzz-introspector and
clarification of why a certain concept is relevant for fuzzing.

The document is arranged to show details about each section in the same
way that the Fuzz introspector HTML report is generated.


## Project functions overview
This table lists information about each function in the project.

#### Func name
Name of the function

#### Functions filename
Filename, on the system, in which the function is defined. In the event of OSS-Fuzz, this
is the filename in the OSS-Fuzz build container.

#### Args
Arguments to the function

#### Function call depth
Call depth the function

#### Reached by Fuzzers
Names of the fuzzers that statically reach this function.

#### Fuzzers runtime hit
Yes/No based on whether the function is hit at runtime.

#### Func lines hit %
The percentage of source code lines of the function that is
executed at runtime.

#### I Count
Instruction count, based on the LLVM IR instructions.

#### BB Count
Basic block count, based on the LLVM basic block count.

#### Cyclomatic complexity
**Definition:** Cyclomatic complexity is a metric for the complexity of software. 
In simple terms it's a metric that is based on discrete graphs and uses the
number of nodes, number of edges and number of connected components to compute
it's given value. In practice, we calculate the cyclomatic complexity over the
control-flow graph of a function, by counting the number of basic blocks, the
number of edges and the number of loops in the control-flow graph.

The more complex code is the higher cyclomatic complexity it will have. The benefit
is that we can quantify code complexity.


**Why is it important for fuzzing?** There is a correlation between complexity
and bug count of code. Therefore, we often look to fuzz code that is the most complex.
We use in fuzz-introspector as it helps search for complex code.

#### Functions reached
The amount of functions that are statically reachable by ths given function.

#### Reached by functions
The amount of functions that statically reach the given function.

#### Accumulated cyclomatic complexity
The sum of cyclomatic complexity of all functions that are statically reachable by the given function.

#### Undiscovered complexity
**Definition:**

The sum of cyclomatic complexity of all functions that are reachable by the given function
subtracted by the cyclomatic complexity of all of the reachable functions that are
also reachable from any of the fuzzers in the project.

## Fuzzer details
#### Call tree overview
**Definition:** Fuzz-introspector includes for each fuzzer a bitmap called the *call tree overview*.
This bitmap is a combination of the call tree extracted through static analysis,
run time coverage data and a way of plotting this data onto a x,y axis with each
y value having the same value but different color.

In short, the call tree overview visualises the call tree nodes on the x-axis
where the nodes are placed by traversing the call tree in a depth-first search (DFS)
manner. DFS is convenient because it makes it easy to follow control-flow by 
looking at the bitmap.

The y-axis is colored based on whether the given node in the call tree was hit
at run time. As such, call tree overview relies on interpreting coverage reports.

**Why is it important for fuzzing?** The call tree overview makes it rapid to
detect whether all nodes in a fuzzers call tree are hit at run time. This is
used to determine if a fuzzer is blocked at some location, i.e. whether there
is a code location the fuzzer should reach in theory (based on approximating
static analysis) but not in practice (at run time).

We can use the call tree to determine if we should change the fuzz driver so it
can invoke the additional paths, or whether using other techniques, e.g. corpus
addition, dictionaries or a completely new fuzzer is needed.


#### Full calltree
Description about full calltree
**Definition:**
**Why is it important for fuzzing?**

#### Fuzz blockers
Description about fuzz blockers
**Definition:**
**Why is it important for fuzzing?**


## Analyses and suggestions
Details about each analysis section.

- [OptimalTargets analysis](/doc/analyses/OptimalTargets.md)

## Runtime coverage analysis
Details about the runtime coverage analysis.
**Definition:**
**Why is it important for fuzzing?**
