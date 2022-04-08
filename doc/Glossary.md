# Glossary

This document provides definitions of concepts in fuzz-introspector and
clarification of why a certain concept is relevant for fuzzing.

The document is arranged to show details about each section in the same
way that the Fuzz introspector HTML report is generated.

## Table of contents
- [Glossary](#glossary)
  * [Project functions overview](#project-functions-overview)
      - [Func name](#func-name)
      - [Functions filename](#functions-filename)
      - [Args](#args)
      - [Function call depth](#function-call-depth)
      - [Reached by Fuzzers](#reached-by-fuzzers)
      - [Fuzzers runtime hit](#fuzzers-runtime-hit)
      - [Func lines hit %](#func-lines-hit--)
      - [I Count](#i-count)
      - [BB Count](#bb-count)
      - [Cyclomatic complexity](#cyclomatic-complexity)
      - [Functions reached](#functions-reached)
      - [Reached by functions](#reached-by-functions)
      - [Accumulated cyclomatic complexity](#accumulated-cyclomatic-complexity)
      - [Undiscovered complexity](#undiscovered-complexity)
  * [Fuzzer details](#fuzzer-details)
      - [Call tree overview](#call-tree-overview)
      - [Full calltree](#full-calltree)
      - [Fuzz blockers](#fuzz-blockers)
  * [Analyses and suggestions](#analyses-and-suggestions)
  * [Runtime coverage analysis](#runtime-coverage-analysis)

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
*Definition:*  
Cyclomatic complexity is a metric for the complexity of software. 
In simple terms it's a metric that is based on discrete graphs and uses the
number of nodes, number of edges and number of connected components to compute
it's given value. In practice, we calculate the cyclomatic complexity over the
control-flow graph of a function, by counting the number of basic blocks, the
number of edges and the number of loops in the control-flow graph.

The more complex code is the higher cyclomatic complexity it will have. The benefit
is that we can quantify code complexity.


*Why is it important for fuzzing?*  
There is a correlation between complexity
and bug count of code. Therefore, we often look to fuzz code that is the most complex.
We use in fuzz-introspector as it helps search for complex code.

#### Functions reached
The amount of functions that are statically reachable by ths given function.

#### Reached by functions
The amount of functions that statically reach the given function.

#### Accumulated cyclomatic complexity
The sum of cyclomatic complexity of all functions that are statically reachable by the given function.

#### Undiscovered complexity
*Definition:*  
The sum of cyclomatic complexity of all functions that are reachable by the given function
subtracted by the cyclomatic complexity of all of the reachable functions that are
also reachable from any of the fuzzers in the project.

## Fuzzer details
### Call tree overview
*Definition:*  
Fuzz-introspector includes for each fuzzer a bitmap called the *call tree overview*.
This bitmap is a combination of the call tree extracted through static analysis,
run time coverage data and a way of plotting this data onto a x,y axis with each
y value having the same value but different color.

In short, the call tree overview visualises the call tree nodes on the x-axis
where the nodes are placed by traversing the call tree in a depth-first search (DFS)
manner. DFS is convenient because it makes it easy to follow control-flow by 
looking at the bitmap.

The y-axis is colored based on whether the given node in the call tree was hit
at run time. As such, call tree overview relies on interpreting coverage reports.

*Why is it important for fuzzing?*  
The call tree overview makes it rapid to
detect whether all nodes in a fuzzers call tree are hit at run time. This is
used to determine if a fuzzer is blocked at some location, i.e. whether there
is a code location the fuzzer should reach in theory (based on approximating
static analysis) but not in practice (at run time).

We can use the call tree to determine if we should change the fuzz driver so it
can invoke the additional paths, or whether using other techniques, e.g. corpus
addition, dictionaries or a completely new fuzzer is needed.


### Full calltree
*Definition:*  
The calltree shows the callsites of a control-flow graph of a given fuzzer. This
is one of the core data structures that Fuzz Introspector use to reason about
fuzzers.

We have a dedicated page for the Calltree [here](/doc/Calltree.md)

### Fuzz blockers
*Definition:*  
A fuzz blocker is a place in the code where a fuzzer should be able to execute code
deeper based on static analysis but at runtime the code that should be reachable
is not executed. It is often a sign of some condition in the code that either:
1) Is a condition that will never be satisfiable in the given fuzzer
2) Is a condition that will be satisfiable if the fuzzer continues to run, but it
has not yet found out how to satisfy the condition.

*Why is it important for fuzzing?*  
We're often interested in identifying these blockers to ensure our fuzzers continue
progressing exploring code.

The most important fuzz blockers are those that hinder the fuzzer in executing a lot
of code. As such, Fuzz Introspector ranks the fuzz blockers based on how much code
they're blocking.

As a fuzz developer, we often need to change certain aspects in our fuzzers to ensure
they're not blocked, or write an entire new fuzzer that executes the code that is blocked.


## Analyses and suggestions
Details about each analysis section.

- [OptimalTargets analysis](/doc/analyses/OptimalTargets.md)

## Runtime coverage analysis
This section provides analysis based mostly on runtime coverage data, but includes some
analysis that uses lightweight static analysis.
The key idea is to show functions that have a high amount of source code lines and that
are covered at runtime, but only a fraction of the source code is actually exercised.


*Why is it important for fuzzing?*  
Complex functions are often responsible for where bugs occur. As such, it's important to
exercises as much of the code in the complex functions, and this analysis is used to highlight
where complex functions *are* hit but not sufficiently.
