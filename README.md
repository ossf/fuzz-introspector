# Fuzz introspector

Fuzz introspector is a tool to help fuzzer developers to get an understanding of their fuzzer’s performance 
and identify any potential blockers. Fuzz introspector aggregates the fuzzers’ functional data like coverage,
hit frequency, entry points, etc to give the developer a birds eye view of their fuzzer. This helps with 
identifying fuzz bottlenecks and blockers and eventually helps in developing better fuzzers.

Fuzz-introspector can on a high-level guide on how to improve fuzzing of a project by guiding on whether you should:
- introduce new fuzzers to a fuzz harness
- modify existing fuzzers to improve the quality of your harness.


By and large these capabilities will remain the goals of fuzz-introspector. The focus is on improving these.

## Features
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

## Testing with OSS-Fuzz
The recommended way of testing this project is by way of OSS-Fuzz. Please see
[OSS-Fuzz instructions](oss_fuzz_integration/) on how to do this. It is the
recommended way because it's by way of OSS-Fuzz that we currently support combining
runtime coverage data with the compiler plugin.


## Testing without OSS-Fuzz integration
You can also build and run the introspector outside the OSS-Fuzz environment.

We use this mainly to develop the LLVM LTO pass as compilation of clang goes
faster (recompilation in particular). However, for the full experience we 
recommend working in the OSS-Fuzz environment as described above.

A complication with testing locally is that the full end-to-end process of
both (1) building fuzzers; (2) running them; (3) building with coverage; and
(4) building with introspector analysis, is better supported
in the OSS-Fuzz environment.


### Build locally

#### Start a python venv
1. Create a venv: `python3 -m venv /path/to/new/virtual/environment`
2. Activate the venv
3. Install dependencies with `pip install -r requirements.txt`

#### Build custom clang
(expect this part to take at least 1 hour)
```
git clone https://github.com/AdaLogics/fuzz-introspector
cd fuzz-introspector
./build_all.sh
```

#### Run local examples
After having built the custom clang above, you can try an example:
```
cd examples
./build_simple_examples.sh
cd simple-example-4/web
python3 -m http.server 5002
```

You can also use the `build_all_projects.sh` and `build_all_web_only.sh` scripts to control
which examples you want to build as well as whether you want to only build the web data.


## Output

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

### Example output

Here we show a few images from the output report:

Project overview:

![project overview](/img/project_overview.png)


Table with data of all functions in a project. The table is sortable to make enhance the process of understanding the fuzzer-infrastructure of a given project:

![Functions table](/img/functions_overview.png)

Reachability tree with coverage overlay

![Overlay 1](/img/overlay-1.png)


Reachability tree with coverage overlay, showing where a fuzz-blocker is occurring
![Overlay 2](/img/overlay-2.png)


## Contribute
### Code of Conduct
Before contributing, please follow our [Code of Conduct](CODE_OF_CONDUCT.md).

### Connect with the Fuzzing Community
If you want to get involved in the Fuzzing community or have ideas to chat about, we discuss
this project in the
[OSSF Security Tooling Working Group](https://github.com/ossf/wg-security-tooling)
meetings.

More specifically, you can attend Fuzzing Collaboration meeting (monthly on
the first Tuesday 10:30am - 11:30am PST
[Calendar](https://calendar.google.com/calendar?cid=czYzdm9lZmhwNWk5cGZsdGI1cTY3bmdwZXNAZ3JvdXAuY2FsZW5kYXIuZ29vZ2xlLmNvbQ),
[Zoom
Link](https://zoom.us/j/99960722134?pwd=ZzZqdzY1eG9tMzQxWFI1Z0RhTkUxZz09)).
