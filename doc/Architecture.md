# Architecture

The overall workflow of fuzz-introspector can be visualised as follows:
![Functions table](/doc/img/fuzz-introspector-architecture.png)

The two main parts to fuzz-introspector is the **compilation-based static analysis**
and **post-processing**. Fuzz-introspector has capabilities to integrate data from
runtime coverage collection, and in order to use this features fuzz-introspector
relies on external infrastructure to extract this coverage. Focus is particularly
on using OSS-Fuzz for this, although fuzz-introspector can be integrated into
other workflows.

## Compilation-based static analysis

The code for this is located in [frontends/llvm](/frontends/llvm)

The compiler-based static analysis is responsible for collecting data about
the code under analysis. The analysis is done by way of an LLVM link-time
optimisations (LTO) pass, which is a convenient tool for making program-wide
analysis. As such, in order to use fuzz-introspector your code must be able
to compile by way of LTO.

The LLVM pass is set to run only when fuzzer executables are linked. However,
at that stage the code in the executables will be compiled with LTO, which
enables the pass to operate on the code of the full program.

To use the fuzz-introspector pass simply compile a given project and the fuzzers
using lto and the gold linker (`-flto` and `-fuse-ld=gold`) clang flags, and then
also set the `FUZZ_INTROSPECTOR` environment variable during the compilation and
linking process. However, we currently rely on adding the LTO pass into the clang
build pass pipeline by patching clang, and consequentially you need to use a custom Clang
for using fuzz-introspector, see [Custom clang](#custom-clang).

### Custom clang

Fuzz-introspector relies on a custom clang in order to run. The reason for this
is that LTO passes loaded from dynamic analysis does not work properly in LLVM
(see [this](https://reviews.llvm.org/D77704) LLVM issue), and thus we need to
patch clang in order to instantiate our pass. As such, it's a minor patch
only involving a few lines of code. We have an issue open
[here](https://github.com/ossf/fuzz-introspector/issues/57) for discussions on this.

The important part of the patch is that we change [these LLVM lines](https://github.com/llvm/llvm-project/blob/be656df18721dc55a1de2eea64a3f73b6afa29a2/llvm/lib/Passes/PassBuilderPipelines.cpp#L1462-L1476)
from 
```c++
ModulePassManager
PassBuilder::buildLTODefaultPipeline(OptimizationLevel Level,
                                     ModuleSummaryIndex *ExportSummary) {
  ModulePassManager MPM;

  // Convert @llvm.global.annotations to !annotation metadata.
  MPM.addPass(Annotation2MetadataPass());

  for (auto &C : FullLinkTimeOptimizationEarlyEPCallbacks)
    C(MPM, Level);

  // Create a function that performs CFI checks for cross-DSO calls with targets
  // in the current module.
  MPM.addPass(CrossDSOCFIPass());
```

to:
```c++
ModulePassManager
PassBuilder::buildLTODefaultPipeline(OptimizationLevel Level,
                                     ModuleSummaryIndex *ExportSummary) {
  ModulePassManager MPM;

  // Convert @llvm.global.annotations to !annotation metadata.
  MPM.addPass(Annotation2MetadataPass());

  for (auto &C : FullLinkTimeOptimizationEarlyEPCallbacks)
    C(MPM, Level);

  // Create a function that performs CFI checks for cross-DSO calls with targets
  // in the current module.
  MPM.addPass(CrossDSOCFIPass());
  MPM.addPass(FuzzIntrospectorPass());
```
i.e. we only add `MPM.addPass(FuzzIntrospectorPass());` to the LTO pass builder pipeline. All
of the LLVM patches are given in [patch-llvm.sh](/frontends/llvm/patch-llvm.sh)

### Output of LLVM plugin
The output of the LLVM pass is composed of two files for each fuzzer executable
analysed:
- fuzzerLogFile-X-YYYYY.data
- fuzzerLogFile-X-YYYYY.data.yaml

where `X` is a counter and `YYYYY` is a uid.

***fuzzerLogFile-X-YYYYY.data***

Holds the calltree of a given fuzzer and the content of it looks as follows:
```
Call tree
LLVMFuzzerTestOneInput /src/htslib/test/fuzz/hts_open_fuzzer.c linenumber=-1
  abort / linenumber=123
  hopen /src/htslib/hfile.c linenumber=127
    find_scheme_handler /src/htslib/hfile.c linenumber=1259
      isalnum_c /src/htslib/./textutils_internal.h linenumber=1125
        __ctype_b_loc / linenumber=161
      tolower_c /src/htslib/./textutils_internal.h linenumber=1126
        __ctype_tolower_loc / linenumber=171
      pthread_mutex_lock / linenumber=1134
      load_hfile_plugins /src/htslib/hfile.c linenumber=1135
        kh_init_scheme_string /src/htslib/hfile.c linenumber=1057
          calloc / linenumber=915
        hfile_add_scheme_handler /src/htslib/hfile.c linenumber=1061
...
...
```

Each row holds three items that are data about a given call site:
- The name of the destination function.
- The file in which the destination function is placed.
- The line in the source code in which the call site is.

Following the above example corresponds to the code [here](https://github.com/samtools/htslib/blob/d7cc10de075735d07eb8da0538cbdc0f331f7bd1/test/fuzz/hts_open_fuzzer.c#L119-L131)
in file `hts_open_fuzzer.c`:
```c
119  int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
120      hFILE *memfile;
121      uint8_t *copy = malloc(size);
122      if (copy == NULL) {
123          abort();
124      }
125      memcpy(copy, data, size);
126      // hopen does not take ownership of `copy`, but hts_hopen does.
127      memfile = hopen("mem:", "rb:", copy, size);
128      if (memfile == NULL) {
129          free(copy);
130          return 0;
131      }
```

The `LLVMFuzzerTestOneInput /src/htslib/test/fuzz/hts_open_fuzzer.c linenumber=-1` is the
entrypoint of the fuzzer. The three data items are:
- destination function is `LLVMFuzzerTestOneInput`
- file in which the destination function resides is `/src/htslib/test/fuzz/hts_open_fuzzer.c` because it corresponds to the location on disk
- linenumber is -1 because there is no call site to LLVMFuzzerTestOneInput as this is called by the fuzz engine, e.g. libFuzzer.

***fuzzerLogFile-X-YYYYY.data.yaml***

Holds information about each function in the module that was compiled by the LTO pass.
The following is example contents extracted from the above example:
```
---
Fuzzer filename: '/src/htslib/test/fuzz/hts_open_fuzzer.c'
All functions:
  Function list name: All functions
  Elements:
    - functionName:    hts_close_or_abort
      functionSourceFile: '/src/htslib/test/fuzz/hts_open_fuzzer.c'
      linkageType:     InternalLinkage
      functionLinenumber: 40
      functionDepth:   18
      returnType:      'N/A'
      argCount:        1
      argTypes:
        - 'struct.htsFile *'
      constantsTouched: []
      argNames:
        - ''
      BBCount:         5
      ICount:          23
      EdgeCount:       5
      CyclomaticComplexity: 2
      functionsReached:
        - BZ2_bzBuffToBuffCompress
        - BZ2_bzBuffToBuffDecompress
        - RC_Decode
        ...
        ...
        - zlib_mem_deflate
        - zlib_mem_inflate
      functionUses:    4
    - functionName:    abort
      functionSourceFile: '/'
      linkageType:     externalLinkage
      functionLinenumber: -1
      functionDepth:   0
      returnType:      'N/A'
```

This is a very verbose file because it enables the post-processing logic to
implement the analysis parts. In this
sense the high-level goal for the compilation-based static analysis is to extract large
volumes of data and then use the post-processing for analysis.



## Post-processing

The code for this is located in [src/fuzz_introspector](/src/fuzz_introspector)

The post-processing logic is responsible for digesting and analysing data from the
compilation-based analysis and also runtime coverage data.
The architectecture goal of the post-processing is to be modular to make analysis plugin
writing easy. For this reason the code is also written in Python to enable rapid
prototyping.

The post-processing takes as input the files output from the compilation-based analysis
(`.data` and `.data.yaml`) as well as coverage reports generated by llvm-cov.
It then digests and performs analysis on all of this, including analysis on a fuzzer-specific
level as well as merging all data into a project-wide analysis.
The post-processing part has some core analysis in the [src/fuzz_introspector](/src/fuzz_introspector) and
also plugin-like analyses in [src/fuzz_introspector/analyses](/src/fuzz_introspector/analyses).

The primary output of the post-processing logic is an HTML report that can be interpreted by humans.
However, there is currently development taking place in extracting data that is useful by fuzzers
to improve the fuzzing, e.g. the analysis plugin [engine_input.py](/src/fuzz_introspector/analyses/engine_input.py)


## Architecture Caveats

The code is in development mode and things can change somewhat rapidly. We try to keep
the documentation up to date, but may miss certain areas. If there are questions about
current status quo please feel free to submit a Github issue with the question.

