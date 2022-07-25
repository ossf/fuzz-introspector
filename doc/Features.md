# Features
**High-level features**

- Show fuzzing-relevant data about each function in a given project
- Show reachability of fuzzer(s)
- Integrate seamlessly with OSS-Fuzz
- Show visualisations to enable fuzzer debugging
- Give suggestions for how to improve fuzzing

**Concrete features**

For each function in a project and a fuzzing harness for the project:
 - show the number of fuzzers (fuzz drivers) that reach this function
 - show cyclomatic complexity of the function
 - show the amount of functions reached by the function
 - show the sum of cyclomatic complexity of all functions reachable by the function
 - show the number of (LLVM IR) basic blocks in the function
 - show the function call-depth of the function
 - show the total unreached complexity of this function, including the complexity from all unreached functions reached by this function.

Given a fuzz harness for a project show:
 - which functions in the project are not reachable by the harness
 - which functions in the project are reachable by harness
 - identify which functions are the best to target (based on which unreached function reaches most code)

Given a fuzz harness statically analyse the code and merge it with run-time coverage information to:
 - visualise statically-extracted calltree of each fuzzer and overlay this calltree with run-time coverage information
 - identify nodes in the statically-extracted calltree where fuzzers are blocked based on run-time coverage information
 - automatically highlight fuzz-blockers, namely locations in the code where fuzzers are not able to continue execution at run-time despite the code being reachable by the fuzzer based on static analysis.

# Output
Screenshots from Fuzz Introspector is is available [here](doc/ExampleOutput.md)

The output of the introspector is a HTML report that gives data about your fuzzer. This includes:

- An overview of reachability by all fuzzers in the repository
- A table with detailed information about each fuzzer in the repository, e.g. number of functions reached, complexity covered and more.
- A table with overview of all functions in the project. With information such as 
  - Number of fuzzers that reaches this function
  - Cyclomatic complexity of this function and all functions reachable by this function
  - Number of functions reached by this function
  - The amount of undiscovered complexity in this function. Undiscovered complexity is the complexity *not* covered by any fuzzers.
- A call reachability tree for each fuzzer in the project. The reachability tree shows the potential control-flow of a given fuzzer
- An overlay of the reachability tree with coverage collected from a fuzzer run.
- A table giving summary information about which targets are optimal targets to analyse for a fuzzer of the functions that are not being reached by any fuzzer.
- A list of suggestions for new fuzzers (this is super naive at the moment).

