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
#include "llvm/Transforms/FuzzIntrospector/FuzzIntrospector.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/DebugLoc.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Operator.h"
#include "llvm/Pass.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/FormatVariadic.h"
#include "llvm/Support/Regex.h"
#include "llvm/Support/YAMLParser.h"
#include "llvm/Support/YAMLTraits.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/InitializePasses.h"
//#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Transforms/Utils/CallGraphUpdater.h"

#include "llvm/InitializePasses.h"
#include "llvm/Pass.h"

#include <algorithm>
#include <bitset>
#include <chrono>
#include <cstdarg>
#include <ctime>
#include <fstream>
#include <iostream>
#include <set>
#include <vector>
#include <unistd.h>


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

struct FuzzIntrospector : public ModulePass {
  static char ID;
  FuzzIntrospector() : ModulePass(ID) {
    errs() << "We are now in the FuzzIntrospector module pass\n";
    initializeFuzzIntrospectorPass(*PassRegistry::getPassRegistry());
  }

  // Class variables
  int moduleLogLevel = 2;
  CalltreeNode FuzzerCalltree;

  std::vector<string> ConfigFuncsToAvoid;
  std::vector<string> ConfigFilesToAvoid;

  // Function defs
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
  std::string GenRandom(const int len);
  void readConfig();
  void makeDefaultConfig();
  bool shouldAvoidFunction(Function *Func);

  void logPrintf(int LogLevel, const char *Fmt, ...);
  bool runOnModule(Module &M) override;

};
} // end of anonymous namespace


INITIALIZE_PASS_BEGIN(FuzzIntrospector, "fuzz-introspector", "fuzz-introspector pass", false, false)

INITIALIZE_PASS_END(FuzzIntrospector, "fuzz-introspector", "fuzz-introspector pass", false, false)
char FuzzIntrospector::ID = 0;

Pass *llvm::createFuzzIntrospectorPass() { return new FuzzIntrospector(); }

void FuzzIntrospector::logPrintf(int LogLevel, const char *Fmt, ...) {
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

void FuzzIntrospector::readConfig() {
  std::string configPath = getenv("FUZZ_INTROSPECTOR_CONFIG");
  ifstream configFile(configPath);

  logPrintf(L1, "Opening the configuration file %s\n", configPath.c_str());

  std::string line;
  std::vector<string> *current = &ConfigFuncsToAvoid;
  bool shouldAnalyse = false;
  while (std::getline(configFile, line)) {
    if (shouldAnalyse) {
      logPrintf(L2, "Inserting avoidance element %s\n", line.c_str());
      current->push_back(line);
    }
    if (line.find("FUNCS_TO_AVOID") != std::string::npos) {
      current = &ConfigFuncsToAvoid;
      shouldAnalyse = true;
    }
    else if (line.find("FILES_TO_AVOID") != std::string::npos) {
      current = &ConfigFilesToAvoid;
      shouldAnalyse = true;
    }
  }
}

void FuzzIntrospector::makeDefaultConfig() {
  logPrintf(L2, "Using default configuration\n");

  std::vector<std::string> FuncsToAvoid = {
    "^_ZNSt3",                       // mangled std::
    "^_ZSt",                         // functions in std:: library
    "^_ZNKSt",                       // std::__xxxbasic_string
    "^_ZTv0_n24_NSt",                // Some virtual functions for basic streams, e.g. virtual thunk to std::__1::basic_ostream<char, std::__1::char_traits<char> >::~basic_ostream()
    "^_ZN18FuzzedDataProvider",      // FuzzedDataProvider
    "^_Zd",                          // "operator delete(...)"
    "^_Zn",                          // operator new (...)"
    "^free$",
    "^malloc$",
    "llvm[.]",
    "sanitizer_cov",
    "sancov[.]module",
  };

  std::vector<string> *current = &ConfigFuncsToAvoid;
  for (auto &s : FuncsToAvoid) {
    current->push_back(s);
  }
}

// Function entrypoint.
bool FuzzIntrospector::runOnModule(Module &M) {
  // Require that FUZZ_INTROSPECTOR environment variable is set
  if (!getenv("FUZZ_INTROSPECTOR")) {
    logPrintf(L1, "Fuzz introspector is not running\n");
    return false;
  }

  logPrintf(L1, "Fuzz introspector is running\n");

  logPrintf(L1, "Running introspector on %s\n", M.getName());
  if (shouldRunIntrospector(M) == false) {
    return false;
  }
  // init randomness
  srand((unsigned)time(NULL) * getpid());

  logPrintf(L1, "This is a fuzzer, performing analysis\n");
  if (getenv("FUZZ_INTROSPECTOR_CONFIG")) {
    logPrintf(L1, "Reading fuzz introspector config file\n");
    readConfig();
  }
  if (!getenv("FUZZ_INTROSPECTOR_CONFIG_NO_DEFAULT")) {
    makeDefaultConfig();
  }

  // Extract and log reachability graph
  std::string nextCalltreeFile = getNextLogFile();

  // Insert the logfile as a global variable. We use this to associate a given binary
  // with a given fuzz report.
  Constant *FuzzIntrospectorTag = ConstantDataArray::getString(M.getContext(), nextCalltreeFile, false);
  llvm::GlobalVariable *GV = new GlobalVariable(
                                      M,
                                      FuzzIntrospectorTag->getType(),
                                      true,
                                      llvm::GlobalValue::LinkageTypes::ExternalLinkage,
                                      FuzzIntrospectorTag,
                                      "FuzzIntrospectorTag");
  GV->setInitializer(FuzzIntrospectorTag);

  extractFuzzerReachabilityGraph(M);
  dumpCalltree(&FuzzerCalltree, nextCalltreeFile);

  // Log data about all functions in the module
  std::string nextYamlName = nextCalltreeFile + ".yaml";
  extractAllFunctionDetailsToYaml(nextYamlName, M);

  logPrintf(L1, "Finished introspector module\n");
  return true;
}

// Write details about all functions in the module to a YAML file
void FuzzIntrospector::extractAllFunctionDetailsToYaml(std::string nextYamlName,
                                                Module &M) {
  std::error_code EC;
  logPrintf(L1, "Logging next yaml tile to %s\n", nextYamlName.c_str());

  auto YamlStream = std::make_unique<raw_fd_ostream>(
      nextYamlName, EC, llvm::sys::fs::OpenFlags::OF_None);
  yaml::Output YamlOut(*YamlStream);

  FuzzerModuleIntrospection fmi(FuzzerCalltree.FileName, wrapAllFunctions(M));
  YamlOut << fmi;
}

FuzzerFunctionList FuzzIntrospector::wrapAllFunctions(Module &M) {
  FuzzerFunctionList ListWrapper;
  ListWrapper.ListName = "All functions";
  logPrintf(L1, "Wrapping all functions\n");
  for (auto &F : M) {
    logPrintf(L3, "Wrapping function %s\n", F.getName().str().c_str());
    if (shouldAvoidFunction(&F)) {
      logPrintf(L3, "Skipping this function\n");
      continue;
    }
    ListWrapper.Functions.push_back(wrapFunction(&F));
  }
  logPrintf(L1, "Ended wrapping all functions\n");

  return ListWrapper;
}

std::string FuzzIntrospector::GenRandom(const int len) {
    static const char alphanum[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";
    std::string tmp_s;
    tmp_s.reserve(len);

    for (int i = 0; i < len; ++i) {
        tmp_s += alphanum[rand() % (sizeof(alphanum) - 1)];
    }
    
    return tmp_s;
}

std::string FuzzIntrospector::getNextLogFile() {
  std::string TargetLogName;
  std::string RandomStr = GenRandom(10);
  int Idx = 0;
  std::string prefix = "";
  if (getenv("FUZZINTRO_OUTDIR")) {
    prefix = std::string(getenv("FUZZINTRO_OUTDIR")) + "/";
  }
  do {
    TargetLogName = formatv("{0}fuzzerLogFile-{1}-{2}.data", prefix, std::to_string(Idx++), RandomStr);
  } while (llvm::sys::fs::exists(TargetLogName));

  // Add a UID to the logname. The reason we do this is when fuzzers are compiled in different
  // locaitons, then the count may end up being the same for different log files at different locations.
  // The problem is that this can be annoying when doing some scripting, e.g. in the oss-fuzz integration
  // at some point. In reality it's not really fuzz introspectors responsibility, however,
  // to make things a bit easier we just do it here.

  return TargetLogName;
}

// Remove a suffix composed of a period and a number, e.g.:
//  - this_func.1234 will be translated to this_func
StringRef FuzzIntrospector::removeDecSuffixFromName(StringRef FuncName) {
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

int FuzzIntrospector::getFunctionLinenumber(Function *F) {
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
std::string FuzzIntrospector::getFunctionFilename(Function *F) {
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
std::string FuzzIntrospector::resolveTypeName(Type *T) {
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
    RetType += "func_type";
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
void FuzzIntrospector::logCalltree(CalltreeNode *Calltree, std::ofstream *CalltreeOut,
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

void FuzzIntrospector::dumpCalltree(CalltreeNode *Calltree, std::string TargetFile) {
  std::ofstream CalltreeOut;
  CalltreeOut.open(TargetFile);
  CalltreeOut << "Call tree\n";
  logCalltree(&FuzzerCalltree, &CalltreeOut, 0);
  CalltreeOut << "====================================\n";
  CalltreeOut.close();
}

Function *FuzzIntrospector::value2Func(Value *Val) {
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
bool FuzzIntrospector::isFunctionPointerType(Type *T) {
  if (PointerType *pointerType = dyn_cast<PointerType>(T)) {
#if LLVM_VERSION_MAJOR >= 15
    if (!pointerType->isOpaque()) {
      return isFunctionPointerType(pointerType->getNonOpaquePointerElementType());
    }
#else
    return isFunctionPointerType(pointerType->getPointerElementType());
#endif
  }
  return T->isFunctionTy();
}

void FuzzIntrospector::getFunctionsInAllNodes(std::vector<CalltreeNode *> *allNodes,
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
Function *FuzzIntrospector::extractVTableIndirectCall(Function *F, Instruction &I) {

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

#if LLVM_VERSION_MAJOR >= 15
  if (pointerType3->isOpaque()) {
    return nullptr;
  }
#endif


#if LLVM_VERSION_MAJOR >= 15
  Type *v13 = pointerType3->getNonOpaquePointerElementType();
#else
  Type *v13 = pointerType3->getPointerElementType();
#endif

  if (!v13->isStructTy()) {
    return nullptr;
  }
  StructType *SSM = cast<StructType>(v13);
  // Now we remove the "class." from the name, and then we have it.
  std::string originalTargetClass = SSM->getName().str().substr(6);
  logPrintf(L3, "Shortened name that we can use for analysis: %s\n", originalTargetClass.c_str());

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
    logPrintf(L3, "The actual function name (from earlyCaught) %s\n", VTableTargetFunc->getName().str().c_str());
  }
  return VTableTargetFunc;
}

// Resolve all outgoing edges in a Function and populate
// the OutgoingEdges vector with them.
void FuzzIntrospector::resolveOutgoingEdges(
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
      // Check if this is a function to avoid before adding it.
      if (shouldAvoidFunction(CSElem)) {
        continue;
      }
      int CSLinenumber = -1;
      const llvm::DebugLoc &debugInfo = I.getDebugLoc();
      // Get the line number of the instruction.
      // We use this when visualizing the calltree.
      //errs() << "\n";
      //I.print(errs());
      if (debugInfo) {
        //errs() << "Printing debugLoc\n";
        //debugInfo.print(errs());
       // errs() << "\n---------------\n";
        if (llvm::DebugLoc InlinedAtDL = debugInfo.getInlinedAt()) {
          //errs() << "Getting inlined line number\n";
          CSLinenumber = InlinedAtDL.getLine();
        }
        else {
          //errs() << "Getting non-inlined line number\n";
          CSLinenumber = debugInfo.getLine();
        }
        //errs() << "line number: " << CSLinenumber << "\n";
      }

      StringRef NormalisedDstName = removeDecSuffixFromName(CSElem->getName());
      CalltreeNode *Node = new CalltreeNode(
          NormalisedDstName, getFunctionFilename(CSElem), CSLinenumber, CSElem);
      //errs() << "Inserting callsite " << NormalisedDstName.str() << " -- line number: " << CSLinenumber << " destination file " << getFunctionFilename(CSElem) << "\n";
      OutgoingEdges->push_back(Node);
    }
  }
}

bool FuzzIntrospector::isNodeInVector(CalltreeNode *Src,
                               std::vector<CalltreeNode *> *Vec) {
  for (CalltreeNode *TmpN : *Vec) {
    if (TmpN->LineNumber == Src->LineNumber &&
        TmpN->FileName.compare(Src->FileName) == 0) {
      return true;
    }
  }
  return false;
}

// Returns true if the function shuold be avoided from analysis
bool FuzzIntrospector::shouldAvoidFunction(Function *Func) {
  std::string TargetFunctionName = Func->getName().str();

  // Avoid by function name
  for (auto &FuncToAvoidRegex : ConfigFuncsToAvoid) {
    Regex Re(FuncToAvoidRegex);
    if (Re.isValid()) {
      if (Re.match(TargetFunctionName)) {
        return true;
      }
    }
  }

  // Avoid by source file
  std::string FuncFilename = getFunctionFilename(Func);
  for (auto &FileToAvoid : ConfigFilesToAvoid) {
    Regex Re(FileToAvoid);
    if (Re.isValid()) {
      if (Re.match(FuncFilename)) {
        return true;
      }
    }
  }
  return false;
}

// Collects all functions reachable by the target function. This
// is an approximation, e.g. we make few efforts into resolving
// indirect calls.
int FuzzIntrospector::extractCalltree(Function *F, CalltreeNode *Calltree,
                               std::vector<CalltreeNode *> *allNodesInTree) {
  std::vector<CalltreeNode *> OutgoingEdges;
  resolveOutgoingEdges(F, &OutgoingEdges);

  int MaxDepthOfEdges = 0;
  for (CalltreeNode *OutEdge : OutgoingEdges) {
    if (isNodeInVector(OutEdge, allNodesInTree)) {
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
FuzzerFunctionWrapper FuzzIntrospector::wrapFunction(Function *F) {
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

// See if there is a main function in this application. If there is a main
// function then it potentially means this is not a libfuzzer fuzzer being
// linked, which is often used in projects to have "standalone-tests". In this
// case we do not want to proceed to avoid having duplicate information.
// There are cases where there will be a main function in the fuzzer, but which
// is weakly defined (see details: https://github.com/ossf/fuzz-introspector/issues/66#issuecomment-1063475323).
// In these cases we check if the main function is empty and if there is an
// LLVMFuzzerTestOneInput function, and, if so, determine that we should do analysis.
// More heuristics may come in the future for determining if a linking operation
// is for a fuzz target.
bool FuzzIntrospector::shouldRunIntrospector(Module &M) {
  Function *FuzzEntryFunc = M.getFunction("LLVMFuzzerTestOneInput");
  Function *MainFunc = M.getFunction("main");
  if (MainFunc != nullptr) {
    std::string MainFuncFilename = getFunctionFilename(MainFunc);
    logPrintf(L1, "Main function filename: %s\n", MainFuncFilename.c_str());

    if (MainFunc->empty()) {
      logPrintf(L1, "Main function is empty. Checking if there is a LLVMFuzzerTestOneInput\n");
      if (FuzzEntryFunc != nullptr) {
        logPrintf(L1, "There is an LLVMFuzzerTestOneInput function. Doing introspector analysis\n");
        return true;
      }
    }
    logPrintf(L1, "Main function is non-empty\n");
    logPrintf(L1, "This means a main function is in the source code rather in the "
                  "libfuzzer "
                  "library, and thus we do not care about it. We only want to "
                  "study the "
                  "actual fuzzers. Exiting this run.\n");
    return false;
  }

  if (FuzzEntryFunc == nullptr) {
    logPrintf(L1, "There is no fuzzer entrypoint.\n");
    return false;
  }

  return true;
}

void FuzzIntrospector::extractFuzzerReachabilityGraph(Module &M) {
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

PreservedAnalyses FuzzIntrospectorPass::run(Module &M, ModuleAnalysisManager &AM) {
  FuzzIntrospector Impl;
  bool Changed = Impl.runOnModule(M);
  if (!Changed)
    return PreservedAnalyses::all();
  return PreservedAnalyses::none();
}
/*
 *
 *
// LLVM currently does not support dynamically loading LTO passes. Thus,
// we dont register it as a pass as we have hardcoded it into Clang instead.
// Ref: https://reviews.llvm.org/D77704
static RegisterPass<FuzzIntrospector> X("fuzz-introspector", "FuzzIntrospector Pass",
                                 false,
                                 false );

static RegisterStandardPasses
    Y(PassManagerBuilder::EP_FullLinkTimeOptimizationEarly,
      [](const PassManagerBuilder &Builder, legacy::PassManagerBase &PM) {
        PM.add(new FuzzIntrospector());
      });
*/
