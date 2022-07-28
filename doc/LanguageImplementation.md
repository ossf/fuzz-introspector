# Language implementation
This document describes the implementation details regarding implementing 
support for a new language in Fuzz Introspector.


In short, to do this a frontend is needed, which is a static analysis component,
and a runtime coverage support is needed. The runtime coverage is not strictly needed,
in that Fuzz Introspector can work without this.


## Overview
Fuzz Introspector is centred around three data structures:
- [Calltree data structure](#calltree-data-structure)
- [Program-wide data file](#program-wide-data-file)
- [Runtime coverage data](#runtime-coverage-data)

Once the support for each of these data structures have been created then
Fuzz Introspector will be able to analyse and digest these. 

The [Calltree data structure](#calltree-data-structure) and [Program-wide data file](#program-wide-data-file)
are extracted using static analysis, which we call our [frontends](/frontends/).

When a new language is integrated into Fuzz Introspector There may be
need for adding frontend-specific logic in the core of Fuzz Introspector.
This is often a consequence of the tools used to create the data 
structure varies a lot from language to language.



## Details
In the following we go into details with each of the data structures.

There is no single way to extract the details of these data structures. For example,
in the current [C/C++ frontend](/frontends/llvm) the [calltree data structure](#calltree-data-structure) and
[program-wide data file](#program-wide-data-file) are extracted by way of link
time analysis with LLVM LTO analysing the LLVM intermediate representation. The
[Python frontend](/frontends/python/) instead relies on analysing the Abstract
Syntax Tree. One consequence of this is that some data items in the data structures
may vary slightly in terms of their semantic meaning. For example, the C/C++
frontend has a clear presentation of what a basic block is, while the Python frontend
does not.

### Example fuzzer
We will use the following example throughout the documentation:
```c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

int target3(const uint8_t *data) {
  if (data[0] == 0x42) return 4;
  return 3;
}

int fuzz_entry(const uint8_t *data, size_t size) {
  int ret;
  if (size == 3) {
    ret = target3(data);
  }
  else {
    ret = 1;
  }
  return ret;
}

extern int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 10) {
      return 0;
    }
    char *s1 = (char*)malloc(123);
    char *s2 = malloc(size+1);
    memcpy(s2, data, size);
    s2[size] = '\0';

    int retval = fuzz_entry(s2, size);

    free(s1);
    free(s2);
    return retval;
}
```


### Calltree data structure
Represents the call tree of a given fuzzer.

A simple format where each line, except fir and last line, represents a callsite.
Each line is composed of four elements seperated by a space, and formally has
the following format:
```
SPACING DST_FUNC SRC_FILE SRC_FILE_LINO
```

The *SPACING* and *DST_FUNC* is not separated by any space.

*SPACING* is the calldepth of the given callsite. Two spaces will be interpreted as one calldepth.

*DST_FUNC* is the name of the destination function of the callsites.

*SRC_FILE* is the path to the source code file of the src of the callsite.

*SRC_FILE_LINO* is the line number in the source code file of the src of the callsite.

For example, the following line:
```
    readFile  /src/ossfuzzlib/utils.c 32
```
refers to a callsite inside the `utils.c` file that targets the function `readFile`.
The function call corresponding to the callsite is placed on line 32 inside of `utils.c`.

#### Example instance of calltree data structure
```
Call tree
LLVMFuzzerTestOneInput /src/introspector_example.c linenumber=-1
  fuzz_entry /src/introspector_example.c linenumber=31
    target3 /src/introspector_example.c linenumber=14
====================================
```

### Program-wide data file
Contains data about each function in the program. The *program* in this context
refers to the executable that will be the fuzzer.

The yaml file has the following format:
```
Fuzzer filename: string
All functions:
  Function list name: All functions
  Elements:
    - ...
    - ...
```
The `Fuzzer filename` field speciies the name of the fuzzer. This is usually the file
path.

The `All functions.Elements` is the important part of the yaml file. This is a list
of elements where each element represents a function in the program. Each element has
the following format:
```yaml
functionName:          string                    # Name of the function
functionSourceFile:    string                    # Source file where the function resides
linkageType:           string                    # function linkage
functionLinenumber:    int                       # Linenumber where the function starts
functionDepth:         int                       # The calldepth of the function
returnType:            string                    # The return type of the function
argCount:              int                       # The number of arguments accepted by the function
argTypes:              list of strings           # The types of the arguments of the function
  - ...
constantsTouched:      list of strings           # The value (bytes) of the constants handled by the function
  - ...
argNames:              list of strings           # The names of the arguments of the function
  - ...
BBCount:               int                       # The number of basic blocks of the function
ICount:                int                       # The number of instructions in the function
EdgeCount:             int                       # The number of branch edges in the function
CyclomaticComplexity:  int                       # The cyclomatic complexity of the function
functionsReached:      list of strings           # A list of all the functions statically reached by this function. This is the names of each function.
  - ...
functionUses:          int                       # The amount of functions that use (reach) this function.
BranchProfiles:        list of branch profiles   # A list of conditional branch profiles used for branch block detection.
  - Branch String:     string                    # source code path and line number of the branch.
    Branch Sides:                                # A pair of data about the branch
      TrueSide:        string                    # Source code path and line number of the True side of the branch condition.
      TrueSideFuncs:   list of strings           # A list of function names, of all functions reachable by the True side of the branch.
        - ...
      FalseSide:       string                    # Source code path and line number of the False side of the branch condition.
      FalseSideFuncs:  list of strings           # A list of function names, of all functions reachable by the False side of the branch.
        - ...
```

#### Example of program-wide data file
The following represents the program-wide data file for the example fuzzer.
```yaml
Fuzzer filename: '/src/introspector_example.c'
All functions:
  Function list name: All functions
  Elements:
    - functionName:    LLVMFuzzerTestOneInput
      functionSourceFile: '/src/introspector_example.c'
      linkageType:     externalLinkage
      functionLinenumber: 22
      functionDepth:   2
      returnType:      'int '
      argCount:        2
      argTypes:
        - 'char *'
        - 'size_t '
      constantsTouched: []
      argNames:
        - ''
        - ''
      BBCount:         6
      ICount:          62
      EdgeCount:       7
      CyclomaticComplexity: 3
      functionsReached:
        - fuzz_entry
        - target3
      functionUses:    0
      BranchProfiles:
        - Branch String:   'introspector_example.c:23,9'
          Branch Sides:
            TrueSide:        'introspector_example.c:24,7'
            TrueSideFuncs:   []
            FalseSide:       'introspector_example.c:26,11'
            FalseSideFuncs:
              - malloc
              - malloc
              - llvm.memcpy.p0i8.p0i8.i64
              - fuzz_entry
              - free
              - free
    - functionName:    fuzz_entry
      functionSourceFile: '/src/introspector_example.c'
      linkageType:     InternalLinkage
      functionLinenumber: 11
      functionDepth:   1
      returnType:      'int '
      argCount:        2
      argTypes:
        - 'char *'
        - 'size_t '
      constantsTouched: []
      argNames:
        - ''
        - ''
      BBCount:         6
      ICount:          36
      EdgeCount:       7
      CyclomaticComplexity: 3
      functionsReached:
        - target3
      functionUses:    1
      BranchProfiles:
        - Branch String:   'introspector_example.c:13,6'
          Branch Sides:
            TrueSide:        'introspector_example.c:14,17'
            TrueSideFuncs:
              - target3
            FalseSide:       'introspector_example.c:17,7'
            FalseSideFuncs:  []
    - functionName:    target3
      functionSourceFile: '/src/introspector_example.c'
      linkageType:     InternalLinkage
      functionLinenumber: 6
      functionDepth:   0
      returnType:      'int '
      argCount:        1
      argTypes:
        - 'char *'
      constantsTouched: []
      argNames:
        - ''
      BBCount:         4
      ICount:          26
      EdgeCount:       4
      CyclomaticComplexity: 2
      functionsReached: []
      functionUses:    1
      BranchProfiles:
        - Branch String:   'introspector_example.c:7,6'
          Branch Sides:
            TrueSide:        'introspector_example.c:7,23'
            TrueSideFuncs:   []
            FalseSide:       'introspector_example.c:8,2'
            FalseSideFuncs:  []
...
```

### Runtime coverage data
The runtime coverage data does not have a strict data structure in Fuzz Introspector. Rather,
we use the [CoverageProfile](https://fuzz-introspector.readthedocs.io/en/latest/core.html#fuzz_introspector.code_coverage.CoverageProfile) class to
handle logic associated with runtime coverage.



## Integrating data structures into Fuzz Introspector workflow

This section describes how to integrate a new language into the Fuzz Introspector
workflow. 


### Integrate frontend
The extraction of [calltree data structure](#calltree-data-structure) and [program-wide data file](#program-wide-data-file)
happens by way of static analysis and the logic around this is placed in [frontends/](/frontends/).

To integrate a frontend simply add the logic in a folder within the [frontends/](/frontends/)
directory.

There are no requirements to in terms of how the actual implementation is done. The only requirement
is that the static analysis must output the two data structures into files called `fuzzerLogFile-UID.data` and
`fuzzerLogFile-UID.data.yaml` for each fuzzer it runs on. The UID should be a unique identifier and this
identifier is used to match the .yaml files and calltree files in fuzz introspector.

We use unique identifiers in this manner because it's versatile when fuzz introspector
integrated into complex build systems, as `fuzzerLogFile-...`s may exits in many
locations within a directory tree. This is because the build system may navigate
folders and run frontend analyses at arbitrary locations.

### Integrate code coverage collection
Integrating code coverage collection is quite individual to each language. The tools we
follow for extracting the code coverage logic is usually dictated by what [OSS-Fuzz](https://github.com/google/oss-fuzz)
supports.

To show the difference in code coverage between languages, this is a snipped of
a code coverage report that Fuzz Introspector interprets in C/C++ runtimes:

```
fuzz_entry:
   11|      1|int fuzz_entry(const uint8_t *data, size_t size) {
   12|      1|  int ret;
   13|      1|  if (size == 3) {
  ------------------
  |  Branch (13:6): [True: 0, False: 1]
  ------------------
   14|      0|          ret = target3(data);
   15|      0|  }
   16|      1|  else {
```
which is extracted by `llvm-cov`. In comparison, the code coverage data used by
Fuzz Introspector for Python analysis is in the form of `json` data e.g.:
```
   },
    "files": {
        "/pythoncovmergedfiles/medio/medio/src/fuzz_desktop_entry.py": {
            "executed_lines": [
                8,
                38,
                39,
                40,
                43,
                44,
                45,
                46,
                47,
                48,
                54,
                55,
                56
            ],
            "summary": {
                "covered_lines": 13,
                "num_statements": 33,
                "percent_covered": 39.39393939393939,
                "percent_covered_display": "39",
                "missing_lines": 20,
                "excluded_lines": 0
            },
```

In order to integrate the coverage we rely on the [code_coverage.py](/src/fuzz_introspector/code_coverage.py) module.
To integrate coverage analysis for your language you need to integrate a loader function that interprets the
coverage data and returns a [CoverageProfile](https://fuzz-introspector.readthedocs.io/en/latest/core.html#fuzz_introspector.code_coverage.CoverageProfile)

Examples of these loader functions are: [load_llvm_coverage](https://fuzz-introspector.readthedocs.io/en/latest/core.html#fuzz_introspector.code_coverage.load_llvm_coverage) and
[load_python_json_coverage](https://fuzz-introspector.readthedocs.io/en/latest/core.html#fuzz_introspector.code_coverage.load_python_json_coverage).

The loader functions is used by [_load_coverage](https://github.com/ossf/fuzz-introspector/blob/011ea59202f73c35ef1ec22de664e3de5927a047/src/fuzz_introspector/datatypes/fuzzer_profile.py#L339)
in the [FuzzerProfile](https://fuzz-introspector.readthedocs.io/en/latest/profiles.html#fuzz_introspector.datatypes.fuzzer_profile.FuzzerProfile) class.

The [CoverageProfile](https://fuzz-introspector.readthedocs.io/en/latest/core.html#fuzz_introspector.code_coverage.CoverageProfile) is still being refined
in order to expose a standard API. The problem is that the underlying coverage
data can be quite different amongst languages. As in the above examples llvm-cov
is based on functions whereas the Python coverage is based on source code files.
To support this the CoverageProfile class can currently exposed coverage
information in two ways, one based on source file reasoning and one based on
function-level reasoning. When you integrate a new code coverage data source it's
likely modifications is needed in the CoverageProfile class too.

### Integrate the language support into OSS-Fuzz
