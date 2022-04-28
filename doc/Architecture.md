# Arthictecture

The overall workflow of fuzz-introspector can be visualised as follows:
![Functions table](/doc/img/fuzz-introspector-architecture.png)

The two main parts to fuzz-introspector is the *compilation-based static analysis*
and *post-processing*. Fuzz-introspector has capabilities to integrate data from
runtime coverage collection, and in order to use this features fuzz-introspector
relies on external infrastructure to extract this coverage. Focus is particularly
on using OSS-Fuzz for this, although fuzz-introspector can be integrated into
other workflows.

**Compilation-based static analysis**

The code for this is located in [llvm](/llvm/)

The compiler-based static analysis is responsible for collecting data about
the code under analysis. The analysis is done by way of an LLVM link-time
optimisations (LTO) pass, which is a convenient tool for making program-wide
analysis. As such, in order to use fuzz-introspector your code must be able
to compile by way of LTO.

The LLVM pass is set to run only when fuzzer executables are linked. However,
at that stage the code in the executables will be compiled with LTO, which
enables the pass operate on the code of the full program.


### Custom clang

Fuzz-introspector relies on a custom clang in order to run. The reason for this
is that LTO passes loaded from dynamic analysis does not work properly in LLVM
(see [this](https://reviews.llvm.org/D77704) LLVM issue), and thus we need to
patch clang in order to instantiate our pass. As such, it's a minor patch
only involving a few lines of code. We have an issue open
[here](https://github.com/ossf/fuzz-introspector/issues/57) for discussions on this.


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

