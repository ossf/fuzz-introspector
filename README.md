# Fuzz introspector

High-level goals:
- Show fuzzing-relevant data about each function in a given project
- Show reachability of fuzzer(s)
- Integrate seamlessly with OSS-Fuzz
- Show visualisations to enable fuzzer debugging
- Give suggestions for how to improve fuzzing

## Testing with OSS-Fuzz
The recommended way of testing this project is by way of OSS-Fuzz. Please see
[OSS-Fuzz instructions](oss_fuzz_integration/) on how to do this. 


## Testing without OSS-Fuzz integration
You can also build and run the introspector outside the OSS-Fuzz environment.

We use this mainly to develop the LLVM LTO pass as compilation of clang goes
faster (recompilation in particular). However, for the full experience we 
recommend working in the OSS-Fuzz environment as described above.

One problem with testing locally is that the full end-to-end process of
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


Table with data of all functions in a project:

![Functions table](/img/functions_overview.png)

Reachability tree with coverage overlay

![Overlay 1](/img/overlay-1.png)


Reachability tree with coverage overlay, showing where a fuzz-blocker is occurring
![Overlay 2](/img/overlay-2.png)
