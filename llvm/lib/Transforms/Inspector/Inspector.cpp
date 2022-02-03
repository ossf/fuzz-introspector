/* Copyright 2021 Fuzz Introspector Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "llvm/ADT/StringExtras.h"
#include "llvm/Transforms/Inspector/Inspector.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/DebugLoc.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/Pass.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/FormatVariadic.h"
#include "llvm/Support/YAMLParser.h"
#include "llvm/Support/YAMLTraits.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Transforms/Utils/CallGraphUpdater.h"
#include <algorithm>
#include <bitset>
#include <chrono>
#include <cstdarg>
#include <ctime>
#include <fstream>
#include <iostream>
#include <set>
#include <vector>

using namespace std;
using namespace llvm;

#define L1 1
#define L2 2
#define L3 3

/*
 * The main goal of this pass is to assist in setting up fuzzing
 * of a project. The pass is run at linking stage, and will do
 * analysis for one fuzzer at the time. That means, the results
 * from a single execution of this pass is only relevant for the
 * given fuzzer that is being linked. In order to do a
 * whole-program fuzzer infrastructure analysis, the results
 * from running this fuzzing introspector plugin across all fuzzers
 * must be merged and post-processed.
 */

using yaml::IO;
using yaml::MappingTraits;
using yaml::Output;

// Typedefs used by the introspector pass
typedef struct fuzzFuncWrapper {
  StringRef FunctionName;
  std::string FunctionSourceFile;
  std::string LinkageType;
  int FunctionLinenumber;
  size_t FunctionDepth;
  std::string ReturnType;
  size_t ArgCount;
  std::vector<std::string> ArgTypes;
  std::vector<std::string> ArgNames;
  std::vector<std::string> ConstantsTouched;
  size_t BBCount;
  size_t ICount;
  size_t EdgeCount;
  size_t CyclomaticComplexity;
  int FunctionUses;
  std::vector<StringRef> FunctionsReached;
} FuzzerFunctionWrapper;

typedef struct FuzzerStringList {
  StringRef ListName;
  std::vector<StringRef> Elements;
} FuzzerStringList;

typedef struct FuzzerFunctionList {
  StringRef ListName;
  std::vector<FuzzerFunctionWrapper> Functions;
} FuzzerFunctionList;

typedef struct FuzzerModuleIntrospection {
  std::string FuzzerFileName;
  FuzzerFunctionList AllFunctions;

  FuzzerModuleIntrospection(std::string A, FuzzerFunctionList B)
      : FuzzerFileName(A), AllFunctions(B) {}
} FuzzerModuleIntrospection;

// YAML mappings for outputting the typedefs above
template <> struct yaml::MappingTraits<FuzzerFunctionWrapper> {
  static void mapping(IO &io, FuzzerFunctionWrapper &Func) {
    io.mapRequired("functionName", Func.FunctionName);
    io.mapRequired("functionSourceFile", Func.FunctionSourceFile);
    io.mapRequired("linkageType", Func.LinkageType);
    io.mapRequired("functionLinenumber", Func.FunctionLinenumber);
    io.mapRequired("functionDepth", Func.FunctionDepth);
    io.mapRequired("returnType", Func.ReturnType);
    io.mapRequired("argCount", Func.ArgCount);
    io.mapRequired("argTypes", Func.ArgTypes);
    io.mapRequired("constantsTouched", Func.ConstantsTouched);
    io.mapRequired("argNames", Func.ArgNames);
    io.mapRequired("BBCount", Func.BBCount);
    io.mapRequired("ICount", Func.ICount);
    io.mapRequired("EdgeCount", Func.EdgeCount);
    io.mapRequired("CyclomaticComplexity", Func.CyclomaticComplexity);
    io.mapRequired("functionsReached", Func.FunctionsReached);
    io.mapRequired("functionUses", Func.FunctionUses);
  }
};
LLVM_YAML_IS_SEQUENCE_VECTOR(FuzzerFunctionWrapper)

template <> struct yaml::MappingTraits<FuzzerStringList> {
  static void mapping(IO &io, FuzzerStringList &l) {
    io.mapRequired("List name", l.ListName);
    io.mapRequired("elements", l.Elements);
  }
};

template <> struct yaml::MappingTraits<FuzzerFunctionList> {
  static void mapping(IO &io, FuzzerFunctionList &FList) {
    io.mapRequired("Function list name", FList.ListName);
    io.mapRequired("Elements", FList.Functions);
  }
};

template <> struct yaml::MappingTraits<FuzzerModuleIntrospection> {
  static void mapping(IO &io, FuzzerModuleIntrospection &introspectorModule) {
    io.mapRequired("Fuzzer filename", introspectorModule.FuzzerFileName);
    io.mapRequired("All functions", introspectorModule.AllFunctions);
  }
};
// end of YAML mappings

namespace {

// Node representation for calltree format
typedef struct CalltreeNode {
  StringRef FunctionName;
  std::string FileName;
  int LineNumber;
  Function *CallsiteDst;
  std::vector<CalltreeNode *> Outgoings;

  CalltreeNode(){};
  CalltreeNode(StringRef A, std::string B, int C, Function *D)
      : FunctionName(A), FileName(B), LineNumber(C), CallsiteDst(D){};

} CalltreeNode;

static FILE *OutputFile = stderr;

struct Inspector : public ModulePass {
  static char ID;

  Inspector() : ModulePass(ID) {
    errs() << "We are now in the Inspector module pass\n";
  }

  int moduleLogLevel = 2;
  CalltreeNode FuzzerCalltree;
  std::set<StringRef> functionNamesToIgnore = {"llvm.", "sanitizer_cov",
                                               "sancov.module"};

  void resolveOutgoingEdges(Function *, std::vector<CalltreeNode *> *);
  bool isNodeInVector(CalltreeNode *Src, std::vector<CalltreeNode *> *Vec);
  void dumpCalltree(CalltreeNode *, std::string);
  void getFunctionsInAllNodes(std::vector<CalltreeNode *> *,
                              std::set<StringRef> *);
  void extractFuzzerReachabilityGraph(Module &M);
  int extractCalltree(Function *F, CalltreeNode *callTree,
                      std::vector<CalltreeNode *> *allNodes);
  void logCalltree(struct CalltreeNode *calltree, std::ofstream *, int Depth);
  FuzzerFunctionWrapper wrapFunction(Function *func);
  void extractAllFunctionDetailsToYaml(std::string nextYamlName, Module &M);
  bool shouldIgnoreFunction(StringRef functionName);
  StringRef removeDecSuffixFromName(StringRef funcName);
  std::string getNextLogFile();
  bool shouldRunIntrospector(Module &M);
  FuzzerFunctionList wrapAllFunctions(Module &M);
  std::string getFunctionFilename(Function *F);
  int getFunctionLinenumber(Function *F);
  std::string resolveTypeName(Type *t);
  Function *value2Func(Value *Val);
  bool isFunctionPointerType(Type *type);
  Function *extractVTableIndirectCall(Function *, Instruction &);


  void logPrintf(int LogLevel, const char *Fmt, ...) {
    if (LogLevel > moduleLogLevel) {
      return;
    }
    // Print time
    struct tm * timeinfo;
    auto SC = std::chrono::system_clock::now();
    std::time_t end_time = std::chrono::system_clock::to_time_t(SC);
    timeinfo = localtime (&end_time);
    char buffer [80];
    strftime (buffer,80,"%H:%M:%S",timeinfo);
    fprintf(OutputFile, "[Log level %d] : %s : ", LogLevel, buffer);

    // Print log statement
    va_list ap;
    va_start(ap, Fmt);
    vfprintf(OutputFile, Fmt, ap);
    va_end(ap);
    fflush(OutputFile);
  }

  // Function entrypoint.
  bool runOnModule(Module &M) override {
    logPrintf(L1, "Running introspector on %s\n", M.getName());
    if (shouldRunIntrospector(M) == false) {
      return true;
    }
    logPrintf(L1, "This is a fuzzer, performing analysis\n");

    // Extract and log reachability graph
    std::string nextCalltreeFile = getNextLogFile();
    extractFuzzerReachabilityGraph(M);
    dumpCalltree(&FuzzerCalltree, nextCalltreeFile);

    // Log data about all functions in the module
    std::string nextYamlName = nextCalltreeFile + ".yaml";
    extractAllFunctionDetailsToYaml(nextYamlName, M);

    logPrintf(L1, "Finished introspector module\n");
    return true;
  }
};
} // end of anonymous namespace

Pass *llvm::createInspectorPass() { return new Inspector(); }

// Write details about all functions in the module to a YAML file
void Inspector::extractAllFunctionDetailsToYaml(std::string nextYamlName,
                                                Module &M) {
  std::error_code EC;
  auto YamlStream = std::make_unique<raw_fd_ostream>(
      nextYamlName, EC, llvm::sys::fs::OpenFlags::OF_None);
  yaml::Output YamlOut(*YamlStream);

  FuzzerModuleIntrospection fmi(FuzzerCalltree.FileName, wrapAllFunctions(M));
  YamlOut << fmi;
}

FuzzerFunctionList Inspector::wrapAllFunctions(Module &M) {
  FuzzerFunctionList ListWrapper;
  ListWrapper.ListName = "All functions";
  logPrintf(1, "Wrapping all functions\n");
  for (auto &F : M) {
    logPrintf(2, "Wrapping function %s\n", F.getName().str().c_str());
    ListWrapper.Functions.push_back(wrapFunction(&F));
  }
  logPrintf(2, "Ended wrapping all functions\n");

  return ListWrapper;
}

std::string Inspector::getNextLogFile() {
  std::string TargetLogName;
  int Idx = 0;
  do {
    TargetLogName = formatv("fuzzerLogFile-{0}.data", std::to_string(Idx++));
  } while (llvm::sys::fs::exists(TargetLogName));
  return TargetLogName;
}

// Remove a suffix composed of a period and a number, e.g.:
//  - this_func.1234 will be translated to this_func
StringRef Inspector::removeDecSuffixFromName(StringRef FuncName) {
  StringRef FuncNameBeforeLastPeriod;
  StringRef FuncNameAfterLastPeriod;

  size_t lastPeriod = FuncName.find_last_of('.', 9999);
  if (lastPeriod == 0) {
    return FuncName;
  }

  FuncNameBeforeLastPeriod = FuncName.substr(0, lastPeriod);
  FuncNameAfterLastPeriod = FuncName.substr(lastPeriod + 1, 99999);
  size_t TmpV;
  if (FuncNameAfterLastPeriod.getAsInteger(10, TmpV)) {
    // getAsInteger returns true if the string is not a number.
    return FuncName;
  }
  return FuncNameBeforeLastPeriod;
}

bool Inspector::shouldIgnoreFunction(StringRef FuncName) {
  for (auto &functionToIgnore : functionNamesToIgnore) {
    if (FuncName.contains(functionToIgnore)) {
      return true;
    }
  }
  return false;
}

int Inspector::getFunctionLinenumber(Function *F) {
  for (auto &I : instructions(*F)) {
    const llvm::DebugLoc &DebugInfo = I.getDebugLoc();
    if (DebugInfo) {
      return DebugInfo.getLine();
    }
  }
  return -1;
}

// Return the path as a string to the file in which
// the function is implemented.
std::string Inspector::getFunctionFilename(Function *F) {
  StringRef Dir;
  StringRef Res;

  int Found = 0;
  for (auto &I : instructions(*F)) {
    const llvm::DebugLoc &DebugInfo = I.getDebugLoc();
    if (DebugInfo) {
      auto *Scope = cast<DIScope>(DebugInfo.getScope());
      // errs() << "Filename: " << Scope->getFilename() << "\n";
      // errs() << "Directory: " << Scope->getDirectory() << "\n";
      // errs() << "Line number: " << debugInfo.getLine() << "\n";
      Dir = Scope->getDirectory();
      Res = Scope->getFilename();
      Found = 1;
      break;
    }
  }

  SmallString<256> *CurrentDir = new SmallString<256>();
  if (Found)
    CurrentDir->append(Dir);
  CurrentDir->append("/");
  if (Found)
    CurrentDir->append(Res);

  StringRef s4 = CurrentDir->str();
  std::string newstr = s4.str();
  return newstr;
}

// Convert an LLVM type into a c-like string
std::string Inspector::resolveTypeName(Type *T) {
  std::string RetType = "";
  std::string RetSuffix = "";
  while (T->isPointerTy()) {
    RetSuffix += "*";
    T = T->getPointerElementType();
  }
  if (T->isIntegerTy()) {
    switch (T->getIntegerBitWidth()) {
    case 8:
      RetType += "char";
      break;
    case 32:
      RetType += "int";
      break;
    case 64:
      RetType += "size_t";
      break;
    default:
      break;
    }
  } else if (T->isStructTy()) {
    if (dyn_cast<StructType>(T)->isLiteral() == false) {
      RetType = T->getStructName().str();
    }
  } else if (T->isFunctionTy()) {
    RetType == "func_type";
  }
  if (RetType == "") {
    return "N/A";
  }
  return RetType + " " + RetSuffix;
}

// Simple recursive function to output the calltree.
// This should be changed to a proper data structure in the future,
// for example something that we can attribute extensively
// would be nice to have.
void Inspector::logCalltree(CalltreeNode *Calltree, std::ofstream *CalltreeOut,
                            int Depth) {
  if (!Calltree) {
    return;
  }
  std::string Spacing = std::string(2 * Depth, ' ');
  *CalltreeOut << Spacing << Calltree->FunctionName.str() << " "
               << Calltree->FileName << " "
               << "linenumber=" << Calltree->LineNumber << "\n";
  for (auto &OutEdge : Calltree->Outgoings) {
    logCalltree(OutEdge, CalltreeOut, Depth + 1);
  }
}

void Inspector::dumpCalltree(CalltreeNode *Calltree, std::string TargetFile) {
  std::ofstream CalltreeOut;
  CalltreeOut.open(TargetFile);
  CalltreeOut << "Call tree\n";
  logCalltree(&FuzzerCalltree, &CalltreeOut, 0);
  CalltreeOut << "====================================\n";
  CalltreeOut.close();
}

Function *Inspector::value2Func(Value *Val) {
  if (isa<llvm::GlobalVariable>(Val))
    return nullptr;
  if (Function *F = dyn_cast<Function>(Val))
    return F;
  if (GlobalAlias *GA = dyn_cast<GlobalAlias>(Val))
    return value2Func(GA->getAliasee());
  if (ConstantExpr *CE = dyn_cast<ConstantExpr>(Val))
    return value2Func(CE->getOperand(0)->stripPointerCasts());
  return nullptr;
}

// Recursively resolve a type and check if it is a function.
bool Inspector::isFunctionPointerType(Type *T) {
  if (PointerType *pointerType = dyn_cast<PointerType>(T)) {
    return isFunctionPointerType(pointerType->getElementType());
  }
  return T->isFunctionTy();
}

void Inspector::getFunctionsInAllNodes(std::vector<CalltreeNode *> *allNodes,
                                       std::set<StringRef> *UniqueNames) {
  for (auto PP : *allNodes) {
    UniqueNames->insert(PP->FunctionName);
  }
}

// Returns the target function of an indirect call that is a VTable call
// The function is a fairly simple approach to identifying the target class
// holding the vtable. This approach is currently limited in that it does not
// recognise the true type and will often identify the top-level function in
// the inheritance levels. For now, it is future work to refine this, however,
// it should be possible to it with a reasonable result and without too much
// hackery.
// ATM, for documentation of this function, please see the URL:
// https://github.com/AdaLogics/fuzz-introspector/issues/XXXX
//
//
//
// This function solves the following problem. Consider the set up:
//
//
//   [some place in the code]
//   %this1 = load %class.dng_info*, %class.dng_info** %this.addr, align 8
//
//   [A virtual call based on a vtable resolution]
//   %43 = bitcast %class.dng_info* %this1 to void (%class.dng_info*, %class.dng_host .....
//   %vtable32 = load void (%class.dng_info*, %class.dng ..... d*, i64, i64, i32)*** %43, 
//   %vfn33 = getelementptr inbounds void (%class.dng .... 4, i64, i32)** %vtable32, i64 8, !dbg !4560
//   %44 = load void (%class.dng_info*, %class ...... i64, i64, i32)** %vfn33,
//   call void %44(%class.dng_info* nonnull dereferenceable(332) %this1,  ...
//
//   with the following global variable declared:
//   _ZTV8dng_info = { [15 x i8*] [i8* null, 
//                                 i8* bitcast ({ i8*, i8* }* @_ZTI8dng_info to i8*), 
//                                 i8* bitcast (void (%class.dng_info*)* @_ZN8dng_infoD1Ev to i8*), 
//                                 i8* bitcast (void (%class.dng_info*)* @_ZN8dng_infoD0Ev to i8*), 
//                                 i8* bitcast (void (%class.dng_info*, %class.dng_host*, %class.dng_stream*)* @_ZN8dng_info5ParseER8dng_hostR10dng_stream to i8*),
//                                 i8* bitcast (void (%class.dng_info*, %class.dng_host*)* @_ZN8dng_info9PostParseER8dng_host to i8*),
//                                 ...
//                                 ...
//   }
//
//   The idea from a high level is to:
//   Based on the instructions making up the indirect call identify that the
//   call is based on a class call class.dng_info. Then, use this name to fetch
//   a global variable called "vtable for dng_info" where this name is mangled.
//   If the global variable is found then get the right index in the vtable
//   based on the index of the "getelementptr" instruction.
Function *Inspector::extractVTableIndirectCall(Function *F, Instruction &I) {

  Value *opnd = cast<CallInst>(&I)->getCalledOperand();

  LoadInst *LI = nullptr;
  if (!(LI = dyn_cast<LoadInst>(opnd)))
    return nullptr;

  // The gep Value is the function pointer, i.e. opnd2 is
  // a virtual function pointer.
  GetElementPtrInst *inst2 = nullptr;
  if (!(inst2 = dyn_cast<GetElementPtrInst>(LI->getPointerOperand())))
    return nullptr;

  uint64_t CIdx = 0;
  if (ConstantInt *CI3 = dyn_cast<ConstantInt>(inst2->getOperand(1))) {
    CIdx = CI3->getZExtValue();
  }

  LoadInst *LI2 = nullptr;
  if (!(LI2 = dyn_cast<LoadInst>(inst2->getPointerOperand()))) {
    return nullptr;
  }
  BitCastInst *BCI = nullptr;
  if (!(BCI = dyn_cast<BitCastInst>(LI2->getPointerOperand()))) {
    return nullptr;
  }

  PointerType *pointerType3 = nullptr;
  if (!(BCI->getSrcTy()->isPointerTy()) ||
      !(pointerType3 = dyn_cast<PointerType>(BCI->getSrcTy()))) {
    return nullptr;
  }
  std::string originalTargetClass;
  Type *v13 = pointerType3->getElementType();
  if (!v13->isStructTy()) {
    return nullptr;
  }
  StructType *SSM = cast<StructType>(v13);
  // Now we remove the "class." from the name, and then we have it.
  originalTargetClass = SSM->getName().str().substr(6);
  logPrintf(L1, "Shortened name that we can use for analysis: %s\n", originalTargetClass.c_str());

  // We find the global variable corresponding to the vtable by
  // way of naming convetions. Specifically, we look for the
  // global variable named "vtable for CLASSNAME" in demangled
  // naming.
  std::string TargetVTableName =
      "_ZTV" + std::to_string(originalTargetClass.size()) + originalTargetClass;
  GlobalVariable *VTableGVar =
      F->getParent()->getGlobalVariable(TargetVTableName, true);
  if (VTableGVar == nullptr) {
    return nullptr;
  }

  // VTables have initialized. Thus, if there is an
  // initializer this is likely a vtable.
  if (!VTableGVar->hasInitializer()) {
    return nullptr;
  }
  Constant *VTableValues = VTableGVar->getInitializer();

  // As of this writing, vtables are structs in LLVM modules.
  if (!VTableValues->getType()->isStructTy()) {
    return nullptr;
  }

  // There is only a single element in the vtable, which
  // is an array of function pointers.
  Constant *VTableValue = VTableValues->getAggregateElement((unsigned int)0);

  // EXtract the function pointer from the VTable. The
  // VTable is the struct itself.
  Constant *FunctionPtrConstant = VTableValue->getAggregateElement(CIdx + 2);

  if (FunctionPtrConstant == nullptr) {
    return nullptr;
  }

  // Extract the function pointer corresponding to the constant expression.
  Function *VTableTargetFunc = value2Func(FunctionPtrConstant);
  if (VTableTargetFunc != nullptr) {
    logPrintf(L1, "The actual function name (from earlyCaught) %s\n", VTableTargetFunc->getName().str().c_str());
  }
  return VTableTargetFunc;
}

// Resolve all outgoing edges in a Function and populate
// the OutgoingEdges vector with them.
void Inspector::resolveOutgoingEdges(
    Function *F, std::vector<CalltreeNode *> *OutgoingEdges) {
  for (auto &I : instructions(F)) {

    std::vector<Function *> FuncPoints;
    Function *CallsiteDst = nullptr;
    // Resolve the function destinations of this callsite.
    if (isa<CallInst>(I) || isa<InvokeInst>(I)) {
      if (CallInst *CDI = dyn_cast<CallInst>(&I)) {
        CallsiteDst = value2Func(CDI->getCalledOperand());
      } else if (InvokeInst *IDI = dyn_cast<InvokeInst>(&I)) {
        CallsiteDst = value2Func(IDI->getCalledOperand());
      }
      if (CallsiteDst != nullptr) {
        FuncPoints.push_back(CallsiteDst);
      }

      // Check for function pointers as arguments in a function call, e.g.
      // to a function that take a function pointer for a callback function.
      if (CallInst *CI = dyn_cast<CallInst>(&I)) {
        for (int i = 0; i < CI->getNumOperands(); i++) {
          Value *opnd = CI->getOperand(i);
          Function *tmpf = value2Func(opnd);
          if (tmpf != nullptr && tmpf != CallsiteDst) {
            FuncPoints.push_back(tmpf);
          }
        }
      }

      // Edge resolution for calls based on VTable indices.
      if (isa<CallInst>(I) && CallsiteDst == nullptr) {
        CallsiteDst = extractVTableIndirectCall(F, I);
        if (CallsiteDst != nullptr) {
          FuncPoints.push_back(CallsiteDst);
        }
      }
    }
    // Check for function pointers in storage instructions.
    if (CallsiteDst == NULL && isa<StoreInst>(I)) {
      if (isFunctionPointerType(I.getOperand(0)->getType())) {
        if (Function *f = dyn_cast<Function>(I.getOperand(0))) {
          FuncPoints.push_back(f);
        }
      }
    }

    for (auto CSElem : FuncPoints) {
      int CSLinenumber = -1;
      const llvm::DebugLoc &debugInfo = I.getDebugLoc();
      // Get the line number of the instruction.
      // We use this when visualizing the calltree.
      if (debugInfo) {
        CSLinenumber = debugInfo.getLine();
      }

      StringRef NormalisedDstName = removeDecSuffixFromName(CSElem->getName());
      CalltreeNode *Node = new CalltreeNode(
          NormalisedDstName, getFunctionFilename(CSElem), CSLinenumber, CSElem);
      OutgoingEdges->push_back(Node);
    }
  }
}

bool Inspector::isNodeInVector(CalltreeNode *Src,
                               std::vector<CalltreeNode *> *Vec) {
  for (CalltreeNode *TmpN : *Vec) {
    if (TmpN->LineNumber == Src->LineNumber &&
        TmpN->FileName.compare(Src->FileName) == 0) {
      return true;
    }
  }
  return false;
}

// Collects all functions reachable by the target function. This
// is an approximation, e.g. we make few efforts into resolving
// indirect calls.
int Inspector::extractCalltree(Function *F, CalltreeNode *Calltree,
                               std::vector<CalltreeNode *> *allNodesInTree) {
  std::vector<CalltreeNode *> OutgoingEdges;
  resolveOutgoingEdges(F, &OutgoingEdges);

  int MaxDepthOfEdges = 0;
  for (CalltreeNode *OutEdge : OutgoingEdges) {
    if (shouldIgnoreFunction(OutEdge->FunctionName) ||
        isNodeInVector(OutEdge, allNodesInTree)) {
      continue;
    }

    allNodesInTree->push_back(OutEdge);
    if (Calltree != nullptr) {
      Calltree->Outgoings.push_back(OutEdge);
    }
    int OutEdgeDepth = 1 + extractCalltree(OutEdge->CallsiteDst, OutEdge,
                                    allNodesInTree);
    MaxDepthOfEdges = std::max(MaxDepthOfEdges, OutEdgeDepth);
  }
  return MaxDepthOfEdges;
}

// Wraps an LLVM function in a struct for conveniently outputting
// to YAML. Also does minor meta-analysis, such as cyclomatic complexity
// analysis.
FuzzerFunctionWrapper Inspector::wrapFunction(Function *F) {
  FuzzerFunctionWrapper FuncWrap;

  FuncWrap.FunctionName = removeDecSuffixFromName(F->getName());
  FuncWrap.FunctionSourceFile = getFunctionFilename(F);
  FuncWrap.FunctionLinenumber = getFunctionLinenumber(F);
  FuncWrap.FunctionUses = 0;
  for (User *U : F->users()) {
    if (Instruction *Inst = dyn_cast<Instruction>(U)) {
      // Uncomment below to get informatino about where it is hit.
      // errs() << "Function " << func->getName() << " is used in: \n";
      // errs() << *Inst << "\n";
      // errs() << "Debug location:\n";
      // const llvm::DebugLoc &debugInfo = Inst->getDebugLoc();
      // if (debugInfo) {
      // auto *Scope = cast<DIScope>(debugInfo.getScope());
      // errs() << "\tFilename: " << Scope->getFilename() << "\n";
      // errs() << "\tDirectory: " << Scope->getDirectory() << "\n";
      // errs() << "\tLine number: " << debugInfo.getLine() << "\n";
      //}
      FuncWrap.FunctionUses += 1;
    }
  }

  FuncWrap.ArgCount = 0;
  for (auto &arg : F->args()) {
    FuncWrap.ArgCount++;
  }

  // Log linkage type
  switch (F->getLinkage()) {
  case llvm::GlobalValue::LinkageTypes::ExternalLinkage:
    FuncWrap.LinkageType = "externalLinkage";
    break;
  case llvm::GlobalValue::LinkageTypes::AvailableExternallyLinkage:
    FuncWrap.LinkageType = "AvailableExternallyLinkage";
    break;
  case llvm::GlobalValue::LinkageTypes::LinkOnceAnyLinkage:
    FuncWrap.LinkageType = "LinkOnceAnyLinkage";
    break;
  case llvm::GlobalValue::LinkageTypes::LinkOnceODRLinkage:
    FuncWrap.LinkageType = "LinkOnceODRLinkage";
    break;
  case llvm::GlobalValue::LinkageTypes::WeakAnyLinkage:
    FuncWrap.LinkageType = "AvailableExternallyLinkage";
    break;
  case llvm::GlobalValue::LinkageTypes::WeakODRLinkage:
    FuncWrap.LinkageType = "WeakODRLinkage";
    break;
  case llvm::GlobalValue::LinkageTypes::AppendingLinkage:
    FuncWrap.LinkageType = "AppendingLinkage";
    break;
  case llvm::GlobalValue::LinkageTypes::InternalLinkage:
    FuncWrap.LinkageType = "InternalLinkage";
    break;
  case llvm::GlobalValue::LinkageTypes::PrivateLinkage:
    FuncWrap.LinkageType = "PrivateLinkage";
    break;
  case llvm::GlobalValue::LinkageTypes::ExternalWeakLinkage:
    FuncWrap.LinkageType = "ExternalWeakLinkage";
    break;
  case llvm::GlobalValue::LinkageTypes::CommonLinkage:
    FuncWrap.LinkageType = "CommonLinkage";
    break;
  default:
    FuncWrap.LinkageType = "Default";
  }

  // Find the depth of the function.
  FuncWrap.ReturnType = resolveTypeName(F->getReturnType());

  // Arguments
  for (auto &A : F->args()) {
    FuncWrap.ArgTypes.push_back(resolveTypeName(A.getType()));
    FuncWrap.ArgNames.push_back(A.getName().str());
  }

  // Log the amount of basic blocks, instruction count and cyclomatic
  // complexity of the function.
  FuncWrap.BBCount = 0;
  FuncWrap.ICount = 0;
  FuncWrap.EdgeCount = 0;
  for (auto &BB : *F) {
    FuncWrap.BBCount++;
    for (auto &I : BB) {
      FuncWrap.ICount++;
      if (BranchInst *BI = dyn_cast<BranchInst>(&I)) {
        FuncWrap.EdgeCount += BI->isConditional() ? 2 : 1;
      }
      if (!getenv("FUZZINTRO_CONSTANTS")) {
        continue;
      }

      //I.dump();
      // Check if the operands refer to a global value and extract data.
      for (int opndIdx = 0; opndIdx < I.getNumOperands(); opndIdx++) {
        Value *opndI = I.getOperand(opndIdx);
        //opndI->dump();
        // Is this a global variable?
        if (GlobalVariable *GV = dyn_cast<GlobalVariable>(opndI)) {
          //GV->dump();
          if (GV->hasInitializer()) {
            Constant *GVI = GV->getInitializer();
            if (ConstantData *GD = dyn_cast<ConstantData>(GVI)) {
              //logPrintf(L1, "ConstantData\n");
              // Integer case
              if (ConstantInt *GI = dyn_cast<ConstantInt>(GD)) {
                logPrintf(L1, "Constant Int\n");
                uint64_t zext_val = GI->getZExtValue();
                errs() << "Zexct val: " << zext_val << "\n";
              }
            }
            else if (ConstantExpr *GE = dyn_cast<ConstantExpr>(GVI)) {
              logPrintf(L1, "Constant expr: %s\n", GE->getName().str().c_str());
              //GE->dump();
              if (GEPOperator* gepo = dyn_cast<GEPOperator>(GE)) {
                errs() << "GEPOperator\n";
                if (GlobalVariable* gv12 = dyn_cast<GlobalVariable>(gepo->getPointerOperand())) {
                  errs() << "GV - " << *gv12 << "\n";
                  if (gv12->hasInitializer()) {
                    errs() << "Has initializer\n";
                    Constant *C222 = gv12->getInitializer();
                    if (ConstantData *GD23 = dyn_cast<ConstantData>(C222)) {
                      errs() << "ConstantData\n";
                      if (ConstantDataArray *Carr = dyn_cast<ConstantDataArray>(GD23)) {
                        // This is constant data. We should be able to dump it down.
                        errs() << "ConstantArray. Type:\n";
                        //Carr->getElementType()->dump();
                        errs() << "Number of elements: " << Carr->getNumElements() << "\n";
                        Type *baseType = Carr->getElementType();
                        if (baseType->isIntegerTy()) {
                            errs() << "Base types\n";
                            for (int i = 0; i < Carr->getNumElements(); i++) {
                              std::string s1 = toHex(Carr->getElementAsInteger(i));
                              errs() << "0x" << s1 << "\n";
                            }
                        }
                        if (Carr->isString()) {
                          errs() << "The string: " << Carr->getAsString() << "\n";
                          FuncWrap.ConstantsTouched.push_back(Carr->getAsString().str());
                        }
                        else {
                          errs() << "No this is not a string\n";
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
  // Do a check on EdgeCount as it may be a bit of a problem. If we have
  // it such that BBCount is more than edges then it probably means
  // we have a switch statement of some sort that we didnt handle above.
  if (FuncWrap.EdgeCount < FuncWrap.BBCount) {
    FuncWrap.EdgeCount += FuncWrap.BBCount;
  }
  FuncWrap.CyclomaticComplexity = FuncWrap.EdgeCount - FuncWrap.BBCount + 2;

  // We have had some issues here with Cyclomatic complexity, so let's do a
  // quick check. Main issue to be resolved.
  if (FuncWrap.CyclomaticComplexity > 999999) {
    FuncWrap.CyclomaticComplexity = 1;
  }

  std::set<StringRef> FuncReaches;
  std::vector<CalltreeNode *> Nodes;
  // TODO: extractCalltree should not be run on all functions in this manner.
  // Rather, we should cache a lot of the analysis we do in extractCalltree
  // because a top-level function would capture all the data we need for the
  // full program.
  FuncWrap.FunctionDepth = extractCalltree(F, nullptr, &Nodes);
  getFunctionsInAllNodes(&Nodes, &FuncReaches);
  std::copy(FuncReaches.begin(), FuncReaches.end(),
            std::back_inserter(FuncWrap.FunctionsReached));

  return FuncWrap;
}

bool Inspector::shouldRunIntrospector(Module &M) {

  // See if there is a main function in this application. If there is a main
  // function then it potentially means this is not a libfuzzer fuzzer being
  // linked, which is often used in projects to have "standalone-tests". In this
  // case we do not want to proceed to avoid having duplicate information.
  Function *MainFunc = M.getFunction("main");
  if (MainFunc != nullptr) {
    logPrintf(L1, "Main function filename: %s\n", getFunctionFilename(MainFunc).c_str());
    logPrintf(L1, "This means a main function is in the source code rather in the "
                  "libfuzzer "
                  "library, and thus we do not care about it. We only want to "
                  "study the "
                  "actual fuzzers. Exiting this run.\n");
    return false;
  }

  return true;
}

void Inspector::extractFuzzerReachabilityGraph(Module &M) {
  Function *FuzzEntryFunc = M.getFunction("LLVMFuzzerTestOneInput");
  if (FuzzEntryFunc == nullptr) {
    return;
  }

  FuzzerCalltree.FunctionName = FuzzEntryFunc->getName();
  FuzzerCalltree.FileName = getFunctionFilename(FuzzEntryFunc);
  FuzzerCalltree.LineNumber = -1;

  std::vector<CalltreeNode *> Nodes;
  extractCalltree(FuzzEntryFunc, &FuzzerCalltree, &Nodes);

  // TODO: handle LLVMFuzzerInitialize as this function may also
  // reach target code, and should be considered another fuzzer entrypoint.
}

char Inspector::ID = 0;
/*
 *
 *
// LLVM currently does not support dynamically loading LTO passes. Thus,
// we dont register it as a pass as we have hardcoded it into Clang instead.
// Ref: https://reviews.llvm.org/D77704
static RegisterPass<Inspector> X("inspector", "Inspector Pass",
                                 false,
                                 false );

static RegisterStandardPasses
    Y(PassManagerBuilder::EP_FullLinkTimeOptimizationEarly,
      [](const PassManagerBuilder &Builder, legacy::PassManagerBase &PM) {
        PM.add(new Inspector());
      });
*/
