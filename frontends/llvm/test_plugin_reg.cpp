// Test-only file: registers FuzzIntrospectorPass with LLVM's new PM plugin API
// so the .so can be loaded via opt --load-pass-plugin.
// NOT compiled into the production LLVM tree.
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Transforms/FuzzIntrospector/FuzzIntrospector.h"

using namespace llvm;

extern "C" LLVM_ATTRIBUTE_WEAK PassPluginLibraryInfo llvmGetPassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "FuzzIntrospector", "0.1",
          [](PassBuilder &PB) {
            PB.registerPipelineParsingCallback(
                [](StringRef Name, ModulePassManager &MPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                  if (Name == "fuzz-introspector") {
                    MPM.addPass(FuzzIntrospectorPass());
                    return true;
                  }
                  return false;
                });
          }};
}
