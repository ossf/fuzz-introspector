# Language implementation
This document describes the implementation details regarding implementing 
support for a new language in Fuzz Introspector. In short, to do this a frontend
is needed, which is a static analysis component, and a runtime coverage support
is needed. The runtime coverage is not strictly needed, in that Fuzz Introspector
can work without this.


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
This, which is often a consequence of the tools used to create the data 
structure varies a lot from language to language.



## Details
In the following we go into details with each of the data structures. We will
use the following example throughout the documentation:
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

#### Example instance of calltree data structure
```
Call tree
LLVMFuzzerTestOneInput /src/introspector_example.c linenumber=-1
  fuzz_entry /src/introspector_example.c linenumber=31
    target3 /src/introspector_example.c linenumber=14
====================================
```

### Program-wide data file
Contains data about each function in the program. The **program** in this context
refers to the executable that will be the fuzzer.

#### Example of program-wide data file
```
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
The [CoverageProfile](https://fuzz-introspector.readthedocs.io/en/latest/core.html#fuzz_introspector.code_coverage.CoverageProfile) class is
used for handling code coverage logic.

The logic in this context
is all handled in `src/fuzz_introspector/code_coverage.py`


## Integrating data structures into Fuzz Introspector workflow
This section describes how to integrate the three data structures into the
Fuzz Introspector workflow.
