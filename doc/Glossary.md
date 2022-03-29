# Glossary

This document provides definitions of concepts in fuzz-introspector and
clarification of why a certain concept is relevant for fuzzing.

## Concepts

### Cyclomatic complexity
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
