# Arthictecture

The overall workflow of fuzz-introspector can be visualised as follows:
![Functions table](/doc/img/fuzz-introspector-architecture.png)

The two main parts to fuzz-introspector is the **compilation-based static analysis**
and **post-processing**. Fuzz-introspector has capabilities to integrate data from
runtime coverage collection, and in order to use this features fuzz-introspector
relies on external infrastructure to extract this coverage. Focus is particularly
on using OSS-Fuzz for this, although fuzz-introspector can be integrated into
other workflows.

## Compilation-based static analysis

The code for this is located in [llvm](/llvm/)

The compiler-based static analysis is responsible for collecting data about
the code under analysis. The analysis is done by way of an LLVM link-time
optimisations (LTO) pass, which is a convenient tool for making program-wide
analysis. As such, in order to use fuzz-introspector your code must be able
to compile by way of LTO.

The LLVM pass is set to run only when fuzzer executables are linked. However,
at that stage the code in the executables will be compiled with LTO, which
enables the pass operate on the code of the full program.

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
of the patches are given in [sed_cmds.sh](/sed_cmds.sh)

### Output of LLVM plugin
The output of the LLVM pass is composed of two files for each fuzzer executable
analysed:
- fuzzerLogDataXXXX
- otherFile2




## Post-processing

The post-processing logic is responsible for digesting data and doing analyses on it.
The architectecture goal of the post-processing is to be modular to make analysis plugin
writing easy.

The code for this is located in [post-processing](/post-processing/)

**Dynamic analysis**

Coverage collection is not done by fuzz-introspector itself and must be run separately.

## Architecture Caveats

The code is in development mode and things can change somewhat rapidly. We try to keep
the documentation up to date, but may miss certain areas. If there are questions about
current status quo please feel free to submit a Github issue with the question.

