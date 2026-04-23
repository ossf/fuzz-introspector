#!/bin/bash -eu
# Copyright 2022 Fuzz Introspector Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################
set -x

if [ -f ./llvm/lib/Transforms/IPO/PassManagerBuilder.cpp ]; then
    echo "Applying llvm 14 pathes"
    echo "add_subdirectory(FuzzIntrospector)" >> ./llvm/lib/Transforms/CMakeLists.txt
    sed -i 's/whole-program devirtualization and bitset lowering./whole-program devirtualization and bitset lowering.\nPM.add(createFuzzIntrospectorPass());/g' ./llvm/lib/Transforms/IPO/PassManagerBuilder.cpp
    sed -i 's/using namespace/#include "llvm\/Transforms\/FuzzIntrospector\/FuzzIntrospector.h"\nusing namespace/g' ./llvm/lib/Transforms/IPO/PassManagerBuilder.cpp
    sed -i 's/Instrumentation/Instrumentation\n  FuzzIntrospector/g' ./llvm/lib/Transforms/IPO/CMakeLists.txt

    sed -i 's/void initializeCrossDSOCFIPass(PassRegistry\&);/void initializeCrossDSOCFIPass(PassRegistry\&);\nvoid initializeFuzzIntrospectorPass(PassRegistry\&);/g' ./llvm/include/llvm/InitializePasses.h
    sed -i 's/#include "llvm\/Transforms\/Instrumentation\/ThreadSanitizer.h"/#include "llvm\/Transforms\/Instrumentation\/ThreadSanitizer.h"\n#include "llvm\/Transforms\/FuzzIntrospector\/FuzzIntrospector.h"/g' ./llvm/lib/Passes/PassBuilder.cpp
    sed -i 's/#include "llvm\/Transforms\/Instrumentation\/PGOInstrumentation.h"/#include "llvm\/Transforms\/Instrumentation\/PGOInstrumentation.h"\n#include "llvm\/Transforms\/FuzzIntrospector\/FuzzIntrospector.h"/g' ./llvm/lib/Passes/PassBuilderPipelines.cpp
    sed -i 's/MPM.addPass(CrossDSOCFIPass());/MPM.addPass(CrossDSOCFIPass());\n  MPM.addPass(FuzzIntrospectorPass());/g' ./llvm/lib/Passes/PassBuilderPipelines.cpp
    sed -i 's/MODULE_PASS("annotation2metadata", Annotation2MetadataPass())/MODULE_PASS("annotation2metadata", Annotation2MetadataPass())\nMODULE_PASS("fuzz-introspector", FuzzIntrospectorPass())/g' ./llvm/lib/Passes/PassRegistry.def
else
    echo "Applying llvm 18+ patches (LLVM 18-22)"
    echo "add_subdirectory(FuzzIntrospector)" >> ./llvm/lib/Transforms/CMakeLists.txt
    sed -i 's/Instrumentation/Instrumentation\n  FuzzIntrospector/g' ./llvm/lib/Transforms/IPO/CMakeLists.txt

    # LLVM 21+: InitializePasses.h uses LLVM_ABI visibility macros.
    # On LLVM 21+, initializeXRayInstrumentationPass was renamed to
    # initializeXRayInstrumentationLegacyPass, so the sed below is a no-op.
    sed -i 's/LLVM_ABI void initializeMIRNamerPass/LLVM_ABI void initializeFuzzIntrospectorPass(PassRegistry \&);\nLLVM_ABI void initializeMIRNamerPass/g' llvm/include/llvm/InitializePasses.h

    # LLVM 18-20: no LLVM_ABI macros; anchor on initializeXRayInstrumentationPass
    # which was present through LLVM 20 but renamed in LLVM 21+.
    # [ ]* handles spacing: LLVM 18-19 use "PassRegistry&", LLVM 20 uses "PassRegistry &".
    sed -i 's/void initializeXRayInstrumentationPass(PassRegistry[ ]*\&);/void initializeXRayInstrumentationPass(PassRegistry \&);\nvoid initializeFuzzIntrospectorPass(PassRegistry \&);/g' ./llvm/include/llvm/InitializePasses.h

    # Verify that exactly one of the two sed commands above injected the declaration.
    grep -q 'initializeFuzzIntrospectorPass' llvm/include/llvm/InitializePasses.h || \
        { echo "ERROR: Failed to inject initializeFuzzIntrospectorPass into InitializePasses.h"; exit 1; }

    sed -i 's/#include "llvm\/Transforms\/Instrumentation\/ThreadSanitizer.h"/#include "llvm\/Transforms\/Instrumentation\/ThreadSanitizer.h"\n#include "llvm\/Transforms\/FuzzIntrospector\/FuzzIntrospector.h"/g' ./llvm/lib/Passes/PassBuilder.cpp
    sed -i 's/#include "llvm\/Transforms\/Instrumentation\/PGOInstrumentation.h"/#include "llvm\/Transforms\/Instrumentation\/PGOInstrumentation.h"\n#include "llvm\/Transforms\/FuzzIntrospector\/FuzzIntrospector.h"/g' ./llvm/lib/Passes/PassBuilderPipelines.cpp
    sed -i 's/MPM.addPass(CrossDSOCFIPass());/MPM.addPass(CrossDSOCFIPass());\n  MPM.addPass(FuzzIntrospectorPass());/g' ./llvm/lib/Passes/PassBuilderPipelines.cpp
    sed -i 's/MODULE_PASS("annotation2metadata", Annotation2MetadataPass())/MODULE_PASS("annotation2metadata", Annotation2MetadataPass())\nMODULE_PASS("fuzz-introspector", FuzzIntrospectorPass())/g' ./llvm/lib/Passes/PassRegistry.def
fi
