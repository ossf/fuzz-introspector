# Fuzz introspector

Fuzz introspector is a tool to help fuzzer developers to get an understanding of their fuzzer’s performance 
and identify any potential blockers. Fuzz introspector aggregates the fuzzers’ functional data like coverage,
hit frequency, entry points, etc to give the developer a birds eye view of their fuzzer. This helps with 
identifying fuzz bottlenecks and blockers and eventually helps in developing better fuzzers.

Fuzz-introspector can on a high-level guide on how to improve fuzzing of a project by guiding on whether you should:
- introduce new fuzzers to a fuzz harness
- modify existing fuzzers to improve the quality of your harness.

By and large these capabilities will remain the goals of fuzz-introspector. The focus is on improving these.

A video demonstration of fuzz-introspector is given [here](https://www.youtube.com/watch?v=cheo-liJhuE)

- [Use with OSS-Fuzz](#testing-with-oss-fuzz)
- [Use without OSS-Fuzz](#testing-without-oss-fuzz-integration)

## Arthictecture
The workflow of fuzz-introspector can be visualised as follows:
![Functions table](/doc/img/fuzz-introspector-architecture.png)

**Compilation-based static analysis**

The compiler-based static analysis is responsible for collecting data about the code under analysis. The analysis is done by way of link-time optimisations, which makes it possible to do program-wide analysis. The analysis collects data about all code that is present in each fuzzer executable at link time.

The code for this is located in [llvm](/llvm/)

**Post-processing**

The post-processing logic is responsible for digesting data and doing analyses on it. The architectecture goal of the post-processing is to be modular to make analysis plugin writing easy.

The code for this is located in [post-processing](/post-processing/)

**Dynamic analysis**

Coverage collection is not done by fuzz-introspector itself and must be run separately.

**Caveats**

The code is in development mode and things can change somewhat rapidly. We try to keep the documentation up to date, but may miss certain areas. If there are questions about current status quo please feel free to submit a Github issue with the question.

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
You can build and run fuzz introspector outside the OSS-Fuzz environment.
We use this mainly to develop the LLVM LTO pass as compilation of clang goes
faster (recompilation in particular). However, for the full experience we 
recommend working in the OSS-Fuzz environment as described above.

A complication with testing locally is that the full end-to-end process of
both (1) building fuzzers; (2) running them; (3) building with coverage; and
(4) building with introspector analysis, is better supported
in the OSS-Fuzz environment.


### Build locally

#### TLDR:
```bash
git clone https://github.com/ossf/fuzz-introspector
cd fuzz-introspector

# Get python dependencies
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt

# Build custom clang with Fuzz introspector LLVM pass
./build_all.sh

cd tests
./build_simple_example.sh
cd simple-example-0/web
python3 -m http.server 8008
```

#### Use Docker

Will use sources cloned to /your/path/to/source

```
docker build  -t "fuzz-introspector:Dockerfile" .
docker run --rm -it -v /your/path/to/source:/src fuzz-introspector:Dockerfile

```

#### Full process


##### step 1: Start a python venv
```bash
git clone https://github.com/ossf/fuzz-introspector

# create virtual environment
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

##### step 2: Build custom clang
Fuzz-introspector relies on an LTO LLVM pass and this requires us to build a custom Clang where the LTO pass is part of the compiler tool chain (see https://github.com/ossf/fuzz-introspector/issues/57 for more details on why this is needed).

To build the custom clang from the root of this repository:

```bash
mkdir build
cd build

# Build binutils
git clone --depth 1 git://sourceware.org/git/binutils-gdb.git binutils
mkdir build
cd ./build
../binutils/configure --enable-gold --enable-plugins --disable-werror
make all-gold
cd ../

# Build LLVM and Clang
git clone https://github.com/llvm/llvm-project/
cd llvm-project/

# Patch Clang to run fuzz introspector
../../sed_cmds.sh
cp -rf ../../llvm/include/llvm/Transforms/FuzzIntrospector/ ./llvm/include/llvm/Transforms/FuzzIntrospector
cp -rf ../../llvm/lib/Transforms/FuzzIntrospector ./llvm/lib/Transforms/FuzzIntrospector
cd ../

# Build LLVM and clang
mkdir llvm-build
cd llvm-build
cmake -G "Unix Makefiles" -DLLVM_ENABLE_PROJECTS="clang;compiler-rt"  \
      -DLLVM_BINUTILS_INCDIR=../binutils/include \
      -DLLVM_TARGETS_TO_BUILD="X86" ../llvm-project/llvm/
make llvm-headers
make -j5
```

##### step 3: Run local example

Now we have two options, to run the fuzz introspector tools without collecting
runtime coverage and doing it with collecting coverage. We go through each of the two options:

##### step 3, option 1, only static analysis
After having built the custom clang above, you build a test case:
```
# From the root of the fuzz-introspector repository
cd tests/simple-example-0

# Run compiler pass to generate *.data and *.data.yaml files
mkdir work
cd work
FUZZ_INTROSPECTOR=1 ../../../build/llvm-build/bin/clang -fsanitize=fuzzer -flto -g ../fuzzer.c -o fuzzer

# Run post-processing to analyse data files and generate HTML report
python3 ../../../post-processing/main.py correlate --binaries_dir=.
python3 ../../../post-processing/main.py report --target_dir=. --correlation_file=./exe_to_fuzz_introspector_logs.yaml

# The post-processing will have generated various .html, .js, .css and .png fies,
# and these are accessible in the current folder. Simply start a webserver and 
# navigate to the report in your local browser (localhost:8008):
python3 -m http.server 8008
```


##### step 3, option 2, include runtime coverage analysis
```
# From the root of the fuzz-introspector repository
cd tests/simple-example-0

# Run compiler pass to generate *.data and *.data.yaml files
mkdir work
cd work

# Run script that will build fuzzer with coverage instrumentation and extract .profraw files
# and convert those to .covreport files with "llvm-cov show"
../build_cov.sh

# Build fuzz-introspector normally
FUZZ_INTROSPECTOR=1 ../../../build/llvm-build/bin/clang -fsanitize=fuzzer -flto -g ../fuzzer.c -o fuzzer

# Run post-processing to analyse data files and generate HTML report
python3 ../../../post-processing/main.py correlate --binaries_dir=.
python3 ../../../post-processing/main.py report --target_dir=. --correlation_file=./exe_to_fuzz_introspector_logs.yaml

# The post-processing will have generated various .html, .js, .css and .png fies,
# and these are accessible in the current folder. Simply start a webserver and
# navigate to the report in your local browser (localhost:8008):
python3 -m http.server 8008
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

![project overview](/doc/img/project_overview.png)


Table with data of all functions in a project. The table is sortable to make enhance the process of understanding the fuzzer-infrastructure of a given project:

![Functions table](/doc/img/functions_overview.png)

Reachability tree with coverage overlay

![Overlay 1](/doc/img/overlay-1.png)


Reachability tree with coverage overlay, showing where a fuzz-blocker is occurring
![Overlay 2](/doc/img/overlay-2.png)


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
