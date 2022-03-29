# Glossary

This document provides definitions of concepts in fuzz-introspector and
clarification of why a certain concept is relevant for fuzzing.

## Concepts

### Cyclomatic complexity
**Definition:** Complexity of a given code
**Why is it important for fuzzing?** There is a correlation between complexity and bug count of code. Therefore, we often look to fuzz code that is the most complex.
