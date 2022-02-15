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

echo "add_subdirectory(Inspector)" >> ./llvm-project/llvm/lib/Transforms/CMakeLists.txt
sed -i 's/whole-program devirtualization and bitset lowering./whole-program devirtualization and bitset lowering.\nPM.add(createInspectorPass());/g' ./llvm-project/llvm/lib/Transforms/IPO/PassManagerBuilder.cpp
sed -i 's/using namespace/#include "llvm\/Transforms\/Inspector\/Inspector.h"\nusing namespace/g' ./llvm-project/llvm/lib/Transforms/IPO/PassManagerBuilder.cpp
sed -i 's/Instrumentation/Instrumentation\n  Inspector/g' ./llvm-project/llvm/lib/Transforms/IPO/CMakeLists.txt

sed -i 's/void initializeCrossDSOCFIPass(PassRegistry\&);/void initializeCrossDSOCFIPass(PassRegistry\&);\nvoid initializeInspectorPass(PassRegistry\&);/g' ./llvm-project/llvm/include/llvm/InitializePasses.h
sed -i 's/#include "llvm\/Transforms\/Instrumentation\/ThreadSanitizer.h"/#include "llvm\/Transforms\/Instrumentation\/ThreadSanitizer.h"\n#include "llvm\/Transforms\/Inspector\/Inspector.h"/g' ./llvm-project/llvm/lib/Passes/PassBuilder.cpp
sed -i 's/#include "llvm\/Transforms\/Instrumentation\/PGOInstrumentation.h"/#include "llvm\/Transforms\/Instrumentation\/PGOInstrumentation.h"\n#include "llvm\/Transforms\/Inspector\/Inspector.h"/g' ./llvm-project/llvm/lib/Passes/PassBuilderPipelines.cpp
sed -i 's/MPM.addPass(CrossDSOCFIPass());/MPM.addPass(CrossDSOCFIPass());\n  MPM.addPass(InspectorPass());/g' ./llvm-project/llvm/lib/Passes/PassBuilderPipelines.cpp
sed -i 's/MODULE_PASS("annotation2metadata", Annotation2MetadataPass())/MODULE_PASS("annotation2metadata", Annotation2MetadataPass())\nMODULE_PASS("inspector", InspectorPass())/g' ./llvm-project/llvm/lib/Passes/PassRegistry.def
