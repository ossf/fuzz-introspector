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

#include "llvm/Transforms/FuzzIntrospector/FuzzIntrospector.h"

#include "llvm/ADT/StringExtras.h"
#include "llvm/BinaryFormat/Dwarf.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/DebugLoc.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Operator.h"
#include "llvm/InitializePasses.h"
#include "llvm/Pass.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/FormatVariadic.h"
#include "llvm/Support/Regex.h"
#include "llvm/Support/YAMLParser.h"
#include "llvm/Support/YAMLTraits.h"
#include "llvm/Support/raw_ostream.h"
// #include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include <unistd.h>

#include <algorithm>
#include <bitset>
#include <chrono>
#include <cstdarg>
#include <ctime>
#include <fstream>
#include <iostream>
#include <set>
#include <vector>

#include "llvm/InitializePasses.h"
#include "llvm/Pass.h"
#include "llvm/Transforms/Utils/CallGraphUpdater.h"

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
typedef struct BranchSide {
  std::string BranchSideString;
  std::vector<StringRef> BranchSideFuncs;
} BranchSide;

typedef struct BranchProfileEntry {
  std::string BranchString;
  std::vector<BranchSide> BranchSides;
} BranchProfileEntry;

typedef struct bCSite {
  std::string src;
  StringRef dst;
} CSite;

typedef struct fuzzFuncWrapper {
  StringRef FunctionName;
  std::string FunctionSourceFile;
  std::string LinkageType;
  int FunctionLinenumber;
  unsigned int FunctionLinenumberEnd;
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
  std::vector<BranchProfileEntry> BranchProfiles;
  std::vector<CSite> Callsites;
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

typedef struct BranchSidesComplexity {
  std::string TrueSideString;
  size_t TrueSideComp;
  std::string FalseSideString;
  size_t FalseSideComp;

  BranchSidesComplexity()
      : TrueSideString(), TrueSideComp(0), FalseSideString(), FalseSideComp(0) {
  }
  BranchSidesComplexity(std::string TS, size_t TC, std::string FS, size_t FC)
      : TrueSideString(TS), TrueSideComp(TC), FalseSideString(FS),
        FalseSideComp(FC) {}
} BranchSidesComplexity;

// YAML mappings for outputting the typedefs above
template <> struct yaml::MappingTraits<FuzzerFunctionWrapper> {
  static void mapping(IO &io, FuzzerFunctionWrapper &Func) {
    io.mapRequired("functionName", Func.FunctionName);
    io.mapRequired("functionSourceFile", Func.FunctionSourceFile);
    io.mapRequired("linkageType", Func.LinkageType);
    io.mapRequired("functionLinenumber", Func.FunctionLinenumber);
    io.mapRequired("functionLinenumberEnd", Func.FunctionLinenumberEnd);
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
    io.mapRequired("BranchProfiles", Func.BranchProfiles);
    io.mapRequired("Callsites", Func.Callsites);
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

template <> struct yaml::MappingTraits<BranchSidesComplexity> {
  static void mapping(IO &io, BranchSidesComplexity &branchSidesComp) {
    io.mapRequired("TrueSide", branchSidesComp.TrueSideString);
    io.mapRequired("TrueSideComp", branchSidesComp.TrueSideComp);
    io.mapRequired("FalseSide", branchSidesComp.FalseSideString);
    io.mapRequired("FalseSideComp", branchSidesComp.FalseSideComp);
  }
};

template <> struct yaml::MappingTraits<BranchSide> {
  static void mapping(IO &io, BranchSide &branchSide) {
    io.mapRequired("BranchSide", branchSide.BranchSideString);
    io.mapRequired("BranchSideFuncs", branchSide.BranchSideFuncs);
  }
};
LLVM_YAML_IS_SEQUENCE_VECTOR(BranchSide)

template <> struct yaml::MappingTraits<BranchProfileEntry> {
  static void mapping(IO &io, BranchProfileEntry &bpe) {
    io.mapRequired("Branch String", bpe.BranchString);
    io.mapRequired("Branch Sides", bpe.BranchSides);
  }
};
LLVM_YAML_IS_SEQUENCE_VECTOR(BranchProfileEntry)

template <> struct yaml::MappingTraits<CSite> {
  static void mapping(IO &io, CSite &cs) {
    io.mapRequired("Src", cs.src);
    io.mapRequired("Dst", cs.dst);
  }
};
LLVM_YAML_IS_SEQUENCE_VECTOR(CSite)

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

std::map<const Function *, size_t> FuncComplexityMap;

struct FuzzIntrospector : public ModulePass {
  static char ID;
  FuzzIntrospector() : ModulePass(ID) {
    initializeFuzzIntrospectorPass(*PassRegistry::getPassRegistry());
  }

  // Class variables
  int moduleLogLevel = 2;
  CalltreeNode FuzzerCalltree;

  std::vector<string> ConfigFuncsToAvoid;
  std::vector<string> ConfigFuncsToAvoid2;
  std::vector<string> ConfigFilesToAvoid;

  // Function defs
  void resolveOutgoingEdges(Function *, std::vector<CalltreeNode *> *);
  bool isNodeInVector(CalltreeNode *Src, std::vector<CalltreeNode *> *Vec);
  void dumpCalltree(CalltreeNode *, std::string);
  void getFunctionsInAllNodes(std::vector<CalltreeNode *> *,
                              std::set<StringRef> *);
  void extractFuzzerReachabilityGraph(Module &M);
  int extractCalltree(Function *F, CalltreeNode *callTree,
                      std::vector<CalltreeNode *> *allNodes, int toRecurse);
  void logCalltree(struct CalltreeNode *calltree, std::ofstream *, int Depth);
  FuzzerFunctionWrapper wrapFunction(Function *func);
  void extractAllFunctionDetailsToYaml(std::string nextYamlName, Module &M);
  StringRef removeDecSuffixFromName(StringRef funcName);
  std::string getNextLogFile();
  bool shouldRunIntrospector(Module &M);

  //  FuzzerFunctionList wrapAllFunctions(Module &M);
  std::string getFunctionFilename(Function *F);
  int getFunctionLinenumberBeginning(Function *F);
  unsigned int getFunctionLinenumberEnd(Function *F);
  std::string resolveTypeName(Type *t);
  Function *value2Func(Value *Val);
  bool isFunctionPointerType(Type *type);
  Function *extractVTableIndirectCall(Function *, Instruction &);
  std::string GenRandom(const int len);
  void readConfig();
  void makeDefaultConfig();
  bool shouldAvoidFunction(Function *Func);
  bool shouldAvoidFunctionDst(std::string targetName);

  void logPrintf(int LogLevel, const char *Fmt, ...);
  bool runOnModule(Module &M) override;

  // Debug related dumping
  void dumpDebugInformation(Module &M, std::string outputFile);
  void printFile(std::ofstream &, StringRef, StringRef, unsigned Line);
  void dumpDIType(std::ofstream &O, DIType *T);
  void recurseDerivedType(std::ofstream &O, DIDerivedType *T);
  void dumpDebugCompileUnits(std::ofstream &O, DebugInfoFinder &Finder);
  void dumpDebugFunctionsDebugInformation(std::ofstream &O,
                                          DebugInfoFinder &Finder);
  void dumpDebugAllTypes(std::ofstream &O, DebugInfoFinder &Finder);
  void dumpDebugAllGlobalVariables(std::ofstream &O, DebugInfoFinder &Finder);

  // void branchProfiler(Module &M);
  std::vector<BranchProfileEntry> branchProfiler(Function *);
  SmallPtrSet<BasicBlock *, 32> findReachables(BasicBlock *);
  vector<StringRef> findReachableFuncs(BasicBlock *);
  std::pair<size_t, size_t> findComplexities(SmallPtrSet<BasicBlock *, 32>,
                                             SmallPtrSet<BasicBlock *, 32>,
                                             std::map<BasicBlock *, size_t>);
  std::pair<std::string, std::string> getInsnDebugInfo(Instruction *I);
  std::pair<std::string, std::string> getBBDebugInfo(BasicBlock *,
                                                     DILocation *);
  void writeOutMap(std::vector<BranchProfileEntry>, std::string);
  size_t calculateBBComplexity(BasicBlock *);
};
} // end of anonymous namespace

INITIALIZE_PASS_BEGIN(FuzzIntrospector, "fuzz-introspector",
                      "fuzz-introspector pass", false, false)

INITIALIZE_PASS_END(FuzzIntrospector, "fuzz-introspector",
                    "fuzz-introspector pass", false, false)
char FuzzIntrospector::ID = 0;

Pass *llvm::createFuzzIntrospectorPass() { return new FuzzIntrospector(); }

void FuzzIntrospector::logPrintf(int LogLevel, const char *Fmt, ...) {
  if (LogLevel > moduleLogLevel) {
    return;
  }
  // Print time
  struct tm *timeinfo;
  auto SC = std::chrono::system_clock::now();
  std::time_t end_time = std::chrono::system_clock::to_time_t(SC);
  timeinfo = localtime(&end_time);
  char buffer[80];
  strftime(buffer, 80, "%H:%M:%S", timeinfo);
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
    } else if (line.find("FILES_TO_AVOID") != std::string::npos) {
      current = &ConfigFilesToAvoid;
      shouldAnalyse = true;
    }
  }
}

void FuzzIntrospector::printFile(std::ofstream &O, StringRef Filename,
                                 StringRef Directory, unsigned Line = 0) {
  if (Filename.empty())
    return;
  O << " from ";
  if (!Directory.empty())
    O << Directory.str() << "/";
  O << Filename.str();
  if (Line)
    O << ":" << Line;
}

void FuzzIntrospector::dumpDebugCompileUnits(std::ofstream &O,
                                             DebugInfoFinder &Finder) {
  for (DICompileUnit *CU : Finder.compile_units()) {
    O << "Compile unit: ";
    auto Lang = dwarf::LanguageString(CU->getSourceLanguage());
    if (!Lang.empty())
      O << Lang.str();
    else
      O << "unknown-language(" << CU->getSourceLanguage() << ")";
    printFile(O, CU->getFilename(), CU->getDirectory());
    O << '\n';
  }
}

void FuzzIntrospector::recurseDerivedType(std::ofstream &O, DIDerivedType *T) {
  if (T == NULL) {
    return;
  }
  auto Tag = dwarf::TagString(T->getTag());
  if (!Tag.empty())
    O << Tag.str() << ", ";
  else
    O << "unknown-tag(" << T->getTag() << ")";

  if (!T->getName().empty()) {
    O << ' ' << T->getName().str();
  } else if (T->getBaseType() != NULL) {
    if (auto *T2 = dyn_cast<DIDerivedType>(T->getBaseType())) {
      return recurseDerivedType(O, T2);
    } else if (auto *BT = dyn_cast<DIBasicType>(T->getBaseType())) {
      if (!BT->getName().empty()) {
        O << ' ' << BT->getName().str();
      }
    }
  } else {
    return;
  }
}

void FuzzIntrospector::dumpDIType(std::ofstream &O, DIType *T) {
  if (T == NULL) {
    return;
  }

  // Skip the type if we don't have the identifier
  if (!T->getName().empty()) {
    O << "Name: { ";
    O << ' ' << T->getName().str();
    O << "}";
  }

  O << "Type: ";
  // if (!T->getName().empty())
  printFile(O, T->getFilename(), T->getDirectory(), T->getLine());
  if (auto *BT = dyn_cast<DIBasicType>(T)) {
    O << " ";
    auto Encoding = dwarf::AttributeEncodingString(BT->getEncoding());
    if (!Encoding.empty())
      O << Encoding.str();
    else
      O << "unknown-encoding(" << BT->getEncoding() << ')';
  } else if (auto *DerivedT = dyn_cast<DIDerivedType>(T)) {
    recurseDerivedType(O, DerivedT);
  } else {
    O << ' ';

    auto Tag = dwarf::TagString(T->getTag());
    if (!Tag.empty())
      O << Tag.str();
    else
      O << "unknown-tag(" << T->getTag() << ")";
  }
  if (auto *CT = dyn_cast<DICompositeType>(T)) {
    O << " Composite type\n";
    if (auto *S = CT->getRawIdentifier()) {
      O << " (identifier: '" << S->getString().str() << "')";
    }
    DINodeArray Elements = CT->getElements();
    O << "Elements: " << Elements.size() << "\n";
    for (uint32_t I = 0; I < Elements.size(); I++) {
      O << "  Elem " << I << "{ ";
      if (auto *TE = dyn_cast<DIType>(Elements[I])) {
        if (!TE->getName().empty())
          O << ' ' << TE->getName().str();
        printFile(O, TE->getFilename(), TE->getDirectory(), TE->getLine());
      }
      if (auto *DE = dyn_cast<DISubprogram>(Elements[I])) {
        O << "Subprogram: " << DE->getName().str();
      }
      if (auto *DENUM = dyn_cast<DIEnumerator>(Elements[I])) {
        O << DENUM->getName().str();
      }
      O << " }\n";
    }
  }
}

void FuzzIntrospector::dumpDebugFunctionsDebugInformation(
    std::ofstream &O, DebugInfoFinder &Finder) {
  O << "## Functions defined in module\n";
  for (DISubprogram *S : Finder.subprograms()) {
    O << "Subprogram: " << S->getName().str() << "\n";
    printFile(O, S->getFilename(), S->getDirectory(), S->getLine());

    if (!S->getLinkageName().empty())
      O << " ('" << S->getLinkageName().str() << "')";
    O << "\n";
    if (auto *FuncType = dyn_cast<DISubroutineType>(S->getType())) {
      if (auto *Types = FuncType->getRawTypeArray()) {
        for (Metadata *Ty : FuncType->getTypeArray()->operands()) {
          O << " - Operand Type: ";
          if (Ty == NULL) {
            O << "void";
            O << "\n";
            continue;
          }
          if (auto DT = dyn_cast<DIType>(Ty)) {
            dumpDIType(O, DT);
          }
          O << "\n";
        }
      }
    } else {
      O << "No subroutine type\n";
    }
    O << '\n';
  }
}

void FuzzIntrospector::dumpDebugAllTypes(std::ofstream &O,
                                         DebugInfoFinder &Finder) {
  O << "## Types defined in module\n";
  for (const DIType *T : Finder.types()) {
    // Skip the type if we don't have the identifier
    if (T->getName().empty())
      continue;

    O << "Type: ";
    // if (!T->getName().empty())
    O << "Name: { ";
    O << ' ' << T->getName().str();
    O << "}";
    printFile(O, T->getFilename(), T->getDirectory(), T->getLine());
    if (auto *BT = dyn_cast<DIBasicType>(T)) {
      O << " ";
      auto Encoding = dwarf::AttributeEncodingString(BT->getEncoding());
      if (!Encoding.empty())
        O << Encoding.str();
      else
        O << "unknown-encoding(" << BT->getEncoding() << ')';
    } else {
      O << ' ';
      auto Tag = dwarf::TagString(T->getTag());
      if (!Tag.empty())
        O << Tag.str();
      else
        O << "unknown-tag(" << T->getTag() << ")";
    }
    if (auto *CT = dyn_cast<DICompositeType>(T)) {
      O << " Composite type\n";
      if (auto *S = CT->getRawIdentifier()) {
        O << " (identifier: '" << S->getString().str() << "')";
      }
      DINodeArray Elements = CT->getElements();
      O << " - Elements: " << Elements.size() << "\n";
      for (uint32_t I = 0; I < Elements.size(); I++) {
        O << " - Elem " << I << "{ ";
        if (auto *TE = dyn_cast<DIType>(Elements[I])) {
          if (!TE->getName().empty())
            O << ' ' << TE->getName().str();
          printFile(O, TE->getFilename(), TE->getDirectory(), TE->getLine());
        }
        if (auto *DE = dyn_cast<DISubprogram>(Elements[I])) {
          O << "Subprogram: " << DE->getName().str();
        }
        if (auto *DENUM = dyn_cast<DIEnumerator>(Elements[I])) {
          O << DENUM->getName().str();
        }
        O << " }\n";
      }
    }
    O << '\n';
  }
}

void FuzzIntrospector::dumpDebugAllGlobalVariables(std::ofstream &O,
                                                   DebugInfoFinder &Finder) {
  O << "## Global variables in module\n";
  for (auto *GVU : Finder.global_variables()) {
    const auto *GV = GVU->getVariable();
    O << "Global variable: " << GV->getName().str();
    printFile(O, GV->getFilename(), GV->getDirectory(), GV->getLine());
    if (!GV->getLinkageName().empty())
      O << " ('" << GV->getLinkageName().str() << "')";
    O << '\n';
  }
}

/*
 * Dumps a lot of debug information from the module in a user-friendly manner.
 * Also applies some reasoning to it, e.g. dump additional information that is
 * related to functions, e.g. it's operands and alike.
 */
void FuzzIntrospector::dumpDebugInformation(Module &M, std::string outputFile) {
  std::ofstream O;
  O.open(outputFile);
  O << "<--- Debug Information for Module 2.0 --->\n";

  DebugInfoFinder Finder;
  Finder.processModule(M);

  dumpDebugCompileUnits(O, Finder);
  O << "\n";
  dumpDebugFunctionsDebugInformation(O, Finder);
  O << "\n";
  dumpDebugAllGlobalVariables(O, Finder);
  O << "\n";
  dumpDebugAllTypes(O, Finder);
  O.close();
}

void FuzzIntrospector::makeDefaultConfig() {
  logPrintf(L2, "Using default configuration\n");

  std::vector<std::string> FuncsToAvoid = {
      "^_ZNSt3",        // mangled std::
      "^_ZSt",          // functions in std:: library
      "^_ZNKSt",        // std::__xxxbasic_string
      "^_ZTv0_n24_NSt", // Some virtual functions for basic streams, e.g.
                        // virtual thunk to std::__1::basic_ostream<char,
                        // std::__1::char_traits<char> >::~basic_ostream()
      "^_ZN18FuzzedDataProvider", // FuzzedDataProvider
      "^_Zd",                     // "operator delete(...)"
      "^_Zn",                     // operator new (...)"
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

  std::vector<std::string> FuncsToAvoid2 = {
      "llvm[.].*",
      "^(__sanitizer_cov)",
      "*sancov[.]module.*",
  };
  std::vector<string> *current2 = &ConfigFuncsToAvoid2;
  for (auto &s : FuncsToAvoid2) {
    current2->push_back(s);
  }
}

// Function entrypoint.
bool FuzzIntrospector::runOnModule(Module &M) {
  // Require that FUZZ_INTROSPECTOR environment variable is set
  if (!getenv("FUZZ_INTROSPECTOR")) {
    return false;
  }
  logPrintf(L1, "Fuzz introspector is running\n");
  if (!getenv("FUZZ_INTROSPECTOR_CONFIG_NO_DEFAULT")) {
    makeDefaultConfig();
  }

  // Set log level if indicated.
  if (getenv("FUZZ_INTROSPECTOR_LOG_LEVEL")) {
    moduleLogLevel = atoi(getenv("FUZZ_INTROSPECTOR_LOG_LEVEL"));
  }

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

  // Extract and log reachability graph
  std::string nextCalltreeFile = getNextLogFile();

  // Insert the logfile as a global variable. We use this to associate a given
  // binary with a given fuzz report.
  Constant *FuzzIntrospectorTag =
      ConstantDataArray::getString(M.getContext(), nextCalltreeFile, false);
  llvm::GlobalVariable *GV =
      new GlobalVariable(M, FuzzIntrospectorTag->getType(), true,
                         llvm::GlobalValue::LinkageTypes::ExternalLinkage,
                         FuzzIntrospectorTag, "FuzzIntrospectorTag");
  GV->setInitializer(FuzzIntrospectorTag);

  extractFuzzerReachabilityGraph(M);
  dumpCalltree(&FuzzerCalltree, nextCalltreeFile);

  // Log data about all functions in the module
  std::string nextYamlName = nextCalltreeFile + ".yaml";
  extractAllFunctionDetailsToYaml(nextYamlName, M);

  // if (getenv("FI_BRANCH_PROFILE")) {
  //   branchProfiler(M);
  // }
  //
  //
  /* Extract debugging information */
  std::string nextDebugFile = nextCalltreeFile + ".debug_info";
  dumpDebugInformation(M, nextDebugFile);

  logPrintf(L1, "Finished introspector module\n");
  return true;
}

// Write details about all functions in the module to a YAML file
void FuzzIntrospector::extractAllFunctionDetailsToYaml(std::string nextYamlName,
                                                       Module &M) {
  std::error_code EC;
  logPrintf(L1, "Logging next yaml tile to %s\n", nextYamlName.c_str());
  logPrintf(L1, "Wrapping all functions\n");

  FuzzerFunctionList ListWrapper;
  ListWrapper.ListName = "All functions";
  for (auto &F : M) {
    logPrintf(L3, "Wrapping function %s\n", F.getName().str().c_str());
    if (shouldAvoidFunction(&F)) {
      logPrintf(L3, "Skipping this function\n");
      continue;
    }
    ListWrapper.Functions.push_back(wrapFunction(&F));
  }
  logPrintf(L1, "Ended wrapping all functions\n");
  // Write the data
  auto YamlStream = std::make_unique<raw_fd_ostream>(
      nextYamlName, EC, llvm::sys::fs::OpenFlags::OF_Append);
  yaml::Output YamlOut(*YamlStream);

  FuzzerModuleIntrospection fmi(FuzzerCalltree.FileName, ListWrapper);
  YamlOut << fmi;

  // return ListWrapper;

  // FuzzerModuleIntrospection fmi(FuzzerCalltree.FileName,
  // wrapAllFunctions(M)); YamlOut << fmi;
}

/*
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
*/
std::string FuzzIntrospector::GenRandom(const int len) {
  static const char alphanum[] = "0123456789"
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
    TargetLogName = formatv("{0}fuzzerLogFile-{1}-{2}.data", prefix,
                            std::to_string(Idx++), RandomStr);
  } while (llvm::sys::fs::exists(TargetLogName));

  // Add a UID to the logname. The reason we do this is when fuzzers are
  // compiled in different locaitons, then the count may end up being the same
  // for different log files at different locations. The problem is that this
  // can be annoying when doing some scripting, e.g. in the oss-fuzz integration
  // at some point. In reality it's not really fuzz introspectors
  // responsibility, however, to make things a bit easier we just do it here.

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

int FuzzIntrospector::getFunctionLinenumberBeginning(Function *F) {
  for (auto &I : instructions(*F)) {
    const llvm::DebugLoc &DebugInfo = I.getDebugLoc();
    if (DebugInfo) {
      return DebugInfo.getLine();
    }
  }
  return -1;
}

unsigned int FuzzIntrospector::getFunctionLinenumberEnd(Function *F) {
  unsigned int MaxLineNumber = 0;

  for (auto &I : instructions(*F)) {
    const llvm::DebugLoc &DebugInfo = I.getDebugLoc();
    if (DebugInfo) {
      if (DebugInfo.getLine() > MaxLineNumber) {
        MaxLineNumber = DebugInfo.getLine();
      }
    }
  }
  return MaxLineNumber;
}

// Return the path as a string to the file in which
// the function is implemented.
std::string FuzzIntrospector::getFunctionFilename(Function *F) {
  StringRef Dir;
  StringRef Res;

  for (auto &I : instructions(*F)) {
    const llvm::DebugLoc &DebugInfo = I.getDebugLoc();
    if (DebugInfo) {
      auto *Scope = cast<DIScope>(DebugInfo.getScope());
      // errs() << "Filename: " << Scope->getFilename() << "\n";
      // errs() << "Directory: " << Scope->getDirectory() << "\n";
      // errs() << "Line number: " << debugInfo.getLine() << "\n";
      Dir = Scope->getDirectory();
      Res = Scope->getFilename();
      break;
    }
  }

  SmallString<256> *CurrentDir = new SmallString<256>();
  if (Dir.size()) {
    CurrentDir->append(Dir);
    CurrentDir->append("/");
  }
  if (Res.size())
    CurrentDir->append(Res);

  StringRef s4 = CurrentDir->str();
  std::string newstr = s4.str();

  delete CurrentDir;

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
    case 1:
      RetType += "bool";
      break;
    case 8:
      RetType += "char";
      break;
    case 16:
      RetType += "short";
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
  } else if (T->isFloatTy()) {
    RetType += "float";
  } else if (T->isDoubleTy()) {
    RetType += "double";
  } else if (T->isVoidTy()) {
    RetType += "void";
  }
  if (RetType == "") {
    return "N/A";
  }
  if (RetSuffix.empty()) {
    return RetType;
  }
  return RetType + " " + RetSuffix;
}

// Simple recursive function to output the calltree.
// This should be changed to a proper data structure in the future,
// for example something that we can attribute extensively
// would be nice to have.
void FuzzIntrospector::logCalltree(CalltreeNode *Calltree,
                                   std::ofstream *CalltreeOut, int Depth) {
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

void FuzzIntrospector::dumpCalltree(CalltreeNode *Calltree,
                                    std::string TargetFile) {
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
      return isFunctionPointerType(
          pointerType->getNonOpaquePointerElementType());
    }
#else
    return isFunctionPointerType(pointerType->getPointerElementType());
#endif
  }
  return T->isFunctionTy();
}

void FuzzIntrospector::getFunctionsInAllNodes(
    std::vector<CalltreeNode *> *allNodes, std::set<StringRef> *UniqueNames) {
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
//   %43 = bitcast %class.dng_info* %this1 to void (%class.dng_info*,
//   %class.dng_host ..... %vtable32 = load void (%class.dng_info*, %class.dng
//   ..... d*, i64, i64, i32)*** %43, %vfn33 = getelementptr inbounds void
//   (%class.dng .... 4, i64, i32)** %vtable32, i64 8, !dbg !4560 %44 = load
//   void (%class.dng_info*, %class ...... i64, i64, i32)** %vfn33, call void
//   %44(%class.dng_info* nonnull dereferenceable(332) %this1,  ...
//
//   with the following global variable declared:
//   _ZTV8dng_info = { [15 x i8*] [i8* null,
//                                 i8* bitcast ({ i8*, i8* }* @_ZTI8dng_info to
//                                 i8*), i8* bitcast (void (%class.dng_info*)*
//                                 @_ZN8dng_infoD1Ev to i8*), i8* bitcast (void
//                                 (%class.dng_info*)* @_ZN8dng_infoD0Ev to
//                                 i8*), i8* bitcast (void (%class.dng_info*,
//                                 %class.dng_host*, %class.dng_stream*)*
//                                 @_ZN8dng_info5ParseER8dng_hostR10dng_stream
//                                 to i8*), i8* bitcast (void (%class.dng_info*,
//                                 %class.dng_host*)*
//                                 @_ZN8dng_info9PostParseER8dng_host to i8*),
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
Function *FuzzIntrospector::extractVTableIndirectCall(Function *F,
                                                      Instruction &I) {
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
  logPrintf(L3, "Shortened name that we can use for analysis: %s\n",
            originalTargetClass.c_str());

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
    logPrintf(L3, "The actual function name (from earlyCaught) %s\n",
              VTableTargetFunc->getName().str().c_str());
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
      // errs() << "\n";
      // I.print(errs());
      if (debugInfo) {
        // errs() << "Printing debugLoc\n";
        // debugInfo.print(errs());
        // errs() << "\n---------------\n";
        if (llvm::DebugLoc InlinedAtDL = debugInfo.getInlinedAt()) {
          // errs() << "Getting inlined line number\n";
          CSLinenumber = InlinedAtDL.getLine();
        } else {
          // errs() << "Getting non-inlined line number\n";
          CSLinenumber = debugInfo.getLine();
        }
        // errs() << "line number: " << CSLinenumber << "\n";
      }

      StringRef NormalisedDstName = removeDecSuffixFromName(CSElem->getName());
      CalltreeNode *Node = new CalltreeNode(
          NormalisedDstName, getFunctionFilename(CSElem), CSLinenumber, CSElem);
      // errs() << "Inserting callsite " << NormalisedDstName.str() << " -- line
      // number: " << CSLinenumber << " destination file " <<
      // getFunctionFilename(CSElem) << "\n";
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

bool FuzzIntrospector::shouldAvoidFunctionDst(std::string DstName) {
  // Avoid by function name
  for (auto &FuncToAvoidRegex : ConfigFuncsToAvoid2) {
    Regex Re(FuncToAvoidRegex);
    if (Re.isValid()) {
      if (Re.match(DstName)) {
        return true;
      }
    }
  }

  return false;
}

// Collects all functions reachable by the target function. This
// is an approximation, e.g. we make few efforts into resolving
// indirect calls.
int FuzzIntrospector::extractCalltree(
    Function *F, CalltreeNode *Calltree,
    std::vector<CalltreeNode *> *allNodesInTree, int toRecurse) {
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
    if (toRecurse) {
      int OutEdgeDepth = 1 + extractCalltree(OutEdge->CallsiteDst, OutEdge,
                                             allNodesInTree, toRecurse);
      MaxDepthOfEdges = std::max(MaxDepthOfEdges, OutEdgeDepth);
    }
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
  FuncWrap.FunctionLinenumber = getFunctionLinenumberBeginning(F);
  FuncWrap.FunctionLinenumberEnd = getFunctionLinenumberEnd(F);
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
  // errs() << "Function:\n";
  // errs() << FuncWrap.FunctionName << "\n";
  for (auto &A : F->args()) {
    FuncWrap.ArgTypes.push_back(resolveTypeName(A.getType()));
    // FuncWrap.ArgNames.push_back(A.getName().str());
    if (A.getName().str().empty()) {
      const DILocalVariable *Var = NULL;
      bool FoundArg = false;
      for (auto &BB : *F) {
        for (auto &I : BB) {
          if (const DbgDeclareInst *DbgDeclare = dyn_cast<DbgDeclareInst>(&I)) {
            if (auto DLV =
                    dyn_cast<DILocalVariable>(DbgDeclare->getVariable())) {
              if (DLV->getArg() == A.getArgNo() + 1 &&
                  !DLV->getName().empty() &&
                  DLV->getScope()->getSubprogram() == F->getSubprogram()) {
                // errs() << "--" << DLV->getName().str() << "\n";
                FuncWrap.ArgNames.push_back(DLV->getName().str());
                FoundArg = true;
              }
            }
          }
        }
      }
      if (FoundArg == false) {
        FuncWrap.ArgNames.push_back("");
      }
    } else {
      // It's non empty, we just push that.
      FuncWrap.ArgNames.push_back(A.getName().str());
    }
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

      // Handle branch instructions. Log src information (source code location)
      // and destination function name.
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

      for (auto CSElem : FuncPoints) {
        // Check if this is a function to avoid before adding it.
        if (shouldAvoidFunction(CSElem)) {
          continue;
        }

        // Extract debug location. Similar logic is found in
        // resolveOutgoingEdges and getInsnDebugInfo but with
        // a few differences in comparison to each. TODO: see
        // if the three places can be merged.
        const llvm::DebugLoc &debugInfo = I.getDebugLoc();
        if (debugInfo) {
          std::string SrcInfo;
          if (llvm::DebugLoc InlinedAtDL = debugInfo.getInlinedAt()) {
            DILocation *DLoc = InlinedAtDL.get();

            SrcInfo = DLoc->getFilename().str() + ":" +
                      std::to_string(InlinedAtDL.getLine()) + "," +
                      std::to_string(InlinedAtDL.getCol());
          } else {
            DILocation *DLoc = debugInfo.get();
            SrcInfo = DLoc->getFilename().str() + ":" +
                      std::to_string(debugInfo.getLine()) + "," +
                      std::to_string(debugInfo.getCol());
          }

          StringRef NormalisedDstName =
              removeDecSuffixFromName(CSElem->getName());

          if (shouldAvoidFunctionDst(NormalisedDstName.str())) {
              continue;
          }
          CSite cs;
          cs.src = SrcInfo;
          cs.dst = NormalisedDstName;

          FuncWrap.Callsites.push_back(cs);
        }
      }

      // Break if we dont want to extract constants, which is currently
      // experimental.
      if (!getenv("FUZZINTRO_CONSTANTS")) {
        continue;
      }

      // I.dump();
      //  Check if the operands refer to a global value and extract data.
      for (int opndIdx = 0; opndIdx < I.getNumOperands(); opndIdx++) {
        Value *opndI = I.getOperand(opndIdx);
        // opndI->dump();
        //  Is this a global variable?
        if (GlobalVariable *GV = dyn_cast<GlobalVariable>(opndI)) {
          // GV->dump();
          if (GV->hasInitializer()) {
            Constant *GVI = GV->getInitializer();
            if (ConstantData *GD = dyn_cast<ConstantData>(GVI)) {
              // logPrintf(L1, "ConstantData\n");
              //  Integer case
              if (ConstantInt *GI = dyn_cast<ConstantInt>(GD)) {
                logPrintf(L1, "Constant Int\n");
                uint64_t zext_val = GI->getZExtValue();
                errs() << "Zexct val: " << zext_val << "\n";
              }
            } else if (ConstantExpr *GE = dyn_cast<ConstantExpr>(GVI)) {
              logPrintf(L1, "Constant expr: %s\n", GE->getName().str().c_str());
              // GE->dump();
              if (GEPOperator *gepo = dyn_cast<GEPOperator>(GE)) {
                errs() << "GEPOperator\n";
                if (GlobalVariable *gv12 =
                        dyn_cast<GlobalVariable>(gepo->getPointerOperand())) {
                  errs() << "GV - " << *gv12 << "\n";
                  if (gv12->hasInitializer()) {
                    errs() << "Has initializer\n";
                    Constant *C222 = gv12->getInitializer();
                    if (ConstantData *GD23 = dyn_cast<ConstantData>(C222)) {
                      errs() << "ConstantData\n";
                      if (ConstantDataArray *Carr =
                              dyn_cast<ConstantDataArray>(GD23)) {
                        // This is constant data. We should be able to dump it
                        // down.
                        errs() << "ConstantArray. Type:\n";
                        // Carr->getElementType()->dump();
                        errs()
                            << "Number of elements: " << Carr->getNumElements()
                            << "\n";
                        Type *baseType = Carr->getElementType();
                        if (baseType->isIntegerTy()) {
                          errs() << "Base types\n";
                          for (int i = 0; i < Carr->getNumElements(); i++) {
                            std::string s1 =
                                toHex(Carr->getElementAsInteger(i));
                            errs() << "0x" << s1 << "\n";
                          }
                        }
                        if (Carr->isString()) {
                          errs()
                              << "The string: " << Carr->getAsString() << "\n";
                          FuncWrap.ConstantsTouched.push_back(
                              Carr->getAsString().str());
                        } else {
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

  FuncComplexityMap[F] = FuncWrap.CyclomaticComplexity;

  std::set<StringRef> FuncReaches;
  std::vector<CalltreeNode *> Nodes;
  // TODO: extractCalltree should not be run on all functions in this manner.
  // Rather, we should cache a lot of the analysis we do in extractCalltree
  // because a top-level function would capture all the data we need for the
  // full program.
  FuncWrap.FunctionDepth = extractCalltree(F, nullptr, &Nodes, 0);
  getFunctionsInAllNodes(&Nodes, &FuncReaches);
  std::copy(FuncReaches.begin(), FuncReaches.end(),
            std::back_inserter(FuncWrap.FunctionsReached));

  // Delete the nodes
  for (auto cNode : Nodes) {
    delete cNode;
  }

  if (getenv("FI_BRANCH_PROFILE")) {
    FuncWrap.BranchProfiles = branchProfiler(F);
  }

  return FuncWrap;
}

// See if there is a main function in this application. If there is a main
// function then it potentially means this is not a libfuzzer fuzzer being
// linked, which is often used in projects to have "standalone-tests". In this
// case we do not want to proceed to avoid having duplicate information.
// There are cases where there will be a main function in the fuzzer, but which
// is weakly defined (see details:
// https://github.com/ossf/fuzz-introspector/issues/66#issuecomment-1063475323).
// In these cases we check if the main function is empty and if there is an
// LLVMFuzzerTestOneInput function, and, if so, determine that we should do
// analysis. More heuristics may come in the future for determining if a linking
// operation is for a fuzz target.
bool FuzzIntrospector::shouldRunIntrospector(Module &M) {
  Function *FuzzEntryFunc = M.getFunction("LLVMFuzzerTestOneInput");
  Function *MainFunc = M.getFunction("main");
  if (MainFunc != nullptr) {
    std::string MainFuncFilename = getFunctionFilename(MainFunc);
    logPrintf(L1, "Main function filename: %s\n", MainFuncFilename.c_str());

    if (MainFunc->empty()) {
      logPrintf(L1, "Main function is empty. Checking if there is a "
                    "LLVMFuzzerTestOneInput\n");
      if (FuzzEntryFunc != nullptr) {
        logPrintf(L1, "There is an LLVMFuzzerTestOneInput function. Doing "
                      "introspector analysis\n");
        return true;
      }
    }
    logPrintf(L1, "Main function is non-empty\n");
    logPrintf(L1,
              "This means a main function is in the source code rather in the "
              "libfuzzer "
              "library, and thus we do not care about it. We only want to "
              "study the "
              "actual fuzzers. Exiting this run.\n");

    if (getenv("FUZZ_INTROSPECTOR_AUTO_FUZZ")) {
      logPrintf(L1,
                "Forcing analysis of all functions. This in auto-fuzz mode");

      std::string TargetLogName;
      std::string RandomStr = GenRandom(10);
      int Idx = 0;
      std::string prefix = "";
      if (getenv("FUZZINTRO_OUTDIR")) {
        prefix = std::string(getenv("FUZZINTRO_OUTDIR")) + "/";
      }
      do {
        TargetLogName = formatv("{0}allFunctionsWithMain-{1}-{2}.yaml", prefix,
                                std::to_string(Idx++), RandomStr);
      } while (llvm::sys::fs::exists(TargetLogName));

      extractAllFunctionDetailsToYaml(TargetLogName, M);
    }
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
  extractCalltree(FuzzEntryFunc, &FuzzerCalltree, &Nodes, 1);

  // TODO: handle LLVMFuzzerInitialize as this function may also
  // reach target code, and should be considered another fuzzer entrypoint.
}

PreservedAnalyses FuzzIntrospectorPass::run(Module &M,
                                            ModuleAnalysisManager &AM) {
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
static RegisterPass<FuzzIntrospector> X("fuzz-introspector", "FuzzIntrospector
Pass", false, false );

static RegisterStandardPasses
    Y(PassManagerBuilder::EP_FullLinkTimeOptimizationEarly,
      [](const PassManagerBuilder &Builder, legacy::PassManagerBase &PM) {
        PM.add(new FuzzIntrospector());
      });
*/

std::vector<BranchProfileEntry> FuzzIntrospector::branchProfiler(Function *F) {
  // std::string OutFileName = getNextLogFile() + ".branchProfile.yaml";
  std::vector<BranchProfileEntry> FuncBranchProfile;

  // logPrintf(L1, "We are in branch profiler.\n");

  // for (const auto &F : M) {
  // Skip declarations or the functions that are not wrapped e.g. not
  // reachable from entry point
  // if (F.isDeclaration() ||
  //     FuncComplexityMap.find(&F) == FuncComplexityMap.end()) {
  //   continue;
  // }
  auto fName = F->getName().str();
  logPrintf(L3, "We are in branch profiler for %s\n", fName.c_str());

  // This map is function level
  std::map<BasicBlock *, size_t> BBComplexityMap;

  for (const auto &BB : *F) {
    auto TI = BB.getTerminator();
    auto BI = dyn_cast<BranchInst>(TI);
    if (BI && BI->isConditional()) {
      auto Side0 = BI->getSuccessor(0);
      auto Side1 = BI->getSuccessor(1);
      auto BILoc = BI->getDebugLoc();

      auto ReachableFuncs0 = findReachableFuncs(Side0);
      auto ReachableFuncs1 = findReachableFuncs(Side1);

      // std::pair<size_t, size_t> Complexities =
      //     findComplexities(Reachable0, Reachable1, BBComplexityMap);

      // auto Side0Comp = Complexities.first;
      // auto Side1Comp = Complexities.second;

      std::pair<std::string, std::string> DbgExtracts;
      DbgExtracts = getInsnDebugInfo((Instruction *)BI);
      std::string BRstring = DbgExtracts.first;
      if (BRstring.length() == 0) {
        continue; // Failed to get debug info
      }
      DbgExtracts = getBBDebugInfo(Side0, BILoc);
      std::string Side0String = DbgExtracts.first;
      if (Side0String.length() == 0)
        continue;
      auto Side0Line = std::stoi(DbgExtracts.second);
      DbgExtracts = getBBDebugInfo(Side1, BILoc);
      std::string Side1String = DbgExtracts.first;
      if (Side1String.length() == 0)
        continue;
      auto Side1Line = std::stoi(DbgExtracts.second);

      // Invariant: side line numbers are ascending.
      std::string TmpString;
      std::vector<StringRef> *TmpFuncs;
      if (Side0Line > Side1Line) {
        TmpString = Side1String;
        TmpFuncs = &ReachableFuncs1;
        Side1String = Side0String;
        ReachableFuncs1 = ReachableFuncs0;
        Side0String = TmpString;
        ReachableFuncs0 = *TmpFuncs;
      }

      // BranchSidesComplexity Entry_val(TrueSideString, *TrueSideFuncs,
      //                                 FalseSideString, *FalseSideFuncs);
      BranchSide BranchSide0Val = {Side0String, ReachableFuncs0};
      BranchSide BranchSide1Val = {Side1String, ReachableFuncs1};
      BranchProfileEntry Entry = {BRstring, {BranchSide0Val, BranchSide1Val}};
      FuncBranchProfile.push_back(Entry);
    }
    // Check for switch statements.
    // IR syntax: switch <intty> <value>, label <defaultdest> [ <intty> <val>,
    // label <dest> ... ] Default dest is operand(1).
    auto SI = dyn_cast<SwitchInst>(TI);
    if (SI) {
      auto SILoc = SI->getDebugLoc();
      std::pair<std::string, std::string> DbgExtracts;
      DbgExtracts = getInsnDebugInfo((Instruction *)SI);
      std::string BRstring = DbgExtracts.first;
      std::vector<std::pair<BasicBlock *, int>> Dest_pairs;
      std::map<BasicBlock *, std::string> DestStringsMap;

      for (unsigned i = 0, NSucc = SI->getNumSuccessors(); i < NSucc; ++i) {
        // This should take care of default dest as well.
        auto Dest = SI->getSuccessor(i);
        DbgExtracts = getBBDebugInfo(Dest, SILoc);
        std::string DestString = DbgExtracts.first;
        if (DestString.length() == 0)
          continue; // No debug info.
        DestStringsMap[Dest] = DestString;
        auto DestLine = std::stoi(DbgExtracts.second);

        Dest_pairs.push_back(make_pair(Dest, DestLine));
      }
      // Sort destinations based on line number.
      std::sort(
          Dest_pairs.begin(), Dest_pairs.end(),
          [](const pair<BasicBlock *, int> &a,
             const pair<BasicBlock *, int> &b) { return a.second < b.second; });

      std::vector<BranchSide> SwitchBranchSides;
      for (auto &pr : Dest_pairs) {
        auto CurrDest = pr.first;
        auto CurrFuncs = findReachableFuncs(CurrDest);
        auto CurrDestString = DestStringsMap[CurrDest];
        SwitchBranchSides.push_back({CurrDestString, CurrFuncs});
      }
      BranchProfileEntry Entry = {BRstring, SwitchBranchSides};
      FuncBranchProfile.push_back(Entry);
    }
  }

  // } // End of loop over M
  // writeOutMap(OutMap, OutFileName);
  return FuncBranchProfile;
}

// Simple intra-procedural CFG traversal
SmallPtrSet<BasicBlock *, 32>
FuzzIntrospector::findReachables(BasicBlock *Src) {
  SmallVector<BasicBlock *, 32> Worklist;
  SmallPtrSet<BasicBlock *, 32> AllReachables;

  Worklist.push_back(Src);

  while (!Worklist.empty()) {
    auto CurrBB = Worklist.pop_back_val();

    // This adds to the set and returns false if already was in the set: avoids
    // loop
    if (!AllReachables.insert(CurrBB).second) {
      continue;
    }

    if (auto TI = CurrBB->getTerminator()) {
      for (unsigned i = 0, NSucc = TI->getNumSuccessors(); i < NSucc; ++i) {
        Worklist.push_back(TI->getSuccessor(i));
      }
    }
  }

  return AllReachables;
}

// Traverse intra-procedural CFG starting from Src and list all called
// functions.
vector<StringRef> FuzzIntrospector::findReachableFuncs(BasicBlock *Src) {
  SmallVector<BasicBlock *, 32> Worklist;
  SmallPtrSet<BasicBlock *, 32> AllReachables;
  vector<StringRef> ReachedFuncs;

  Worklist.push_back(Src);

  while (!Worklist.empty()) {
    auto CurrBB = Worklist.pop_back_val();

    // This adds to the set and returns false if already was in the set: avoids
    // loop
    if (!AllReachables.insert(CurrBB).second) {
      continue;
    }

    for (auto &I : *CurrBB) {
      // Skip debugging insns
      if (isa<DbgInfoIntrinsic>(&I)) {
        continue;
      }

      if (isa<CallInst>(I) || isa<InvokeInst>(I)) {
        Function *Callee = nullptr;
        if (auto CI = dyn_cast<CallInst>(&I)) {
          Callee = value2Func(CI->getCalledOperand());
        } else if (auto II = dyn_cast<InvokeInst>(&I)) {
          Callee = value2Func(II->getCalledOperand());
        }

        if (Callee) {
          ReachedFuncs.push_back(Callee->getName());
        }
      }
    }

    if (auto TI = CurrBB->getTerminator()) {
      for (unsigned i = 0, NSucc = TI->getNumSuccessors(); i < NSucc; ++i) {
        Worklist.push_back(TI->getSuccessor(i));
      }
    }
  }

  return ReachedFuncs;
}

// Calculate complexities reachable from each reachable unique BBs
// TODO: for now, this function just accounts for complexity of callee functions
// from the reachable BBs. We can do better by carefully calculating complexity
// of the reachable regions of the code i.e. intra-procedural complexity by
// counting the number of unique edges and nodes for each reachable set.
std::pair<size_t, size_t> FuzzIntrospector::findComplexities(
    SmallPtrSet<BasicBlock *, 32> TrueReachable,
    SmallPtrSet<BasicBlock *, 32> FalseReachable,
    std::map<BasicBlock *, size_t> BBComplexityMap) {
  size_t TrueComp = 0, FalseComp = 0;

  // iterate and skip those reachable by false side
  for (auto BB : TrueReachable) {
    if (FalseReachable.find(BB) != FalseReachable.end()) {
      continue;
    }

    if (BBComplexityMap.find(BB) == BBComplexityMap.end()) {
      BBComplexityMap[BB] = calculateBBComplexity(BB);
    }
    TrueComp += BBComplexityMap[BB];
  }

  // iterate and skip those reachable by true side
  for (auto BB : FalseReachable) {
    if (TrueReachable.find(BB) != TrueReachable.end()) {
      continue;
    }

    if (BBComplexityMap.find(BB) == BBComplexityMap.end()) {
      BBComplexityMap[BB] = calculateBBComplexity(BB);
    }
    FalseComp += BBComplexityMap[BB];
  }

  return make_pair(TrueComp, FalseComp);
}

std::pair<std::string, std::string>
FuzzIntrospector::getInsnDebugInfo(Instruction *I) {
  std::string Ret_string = "", Ret_line = "";

  DILocation *Loc = I->getDebugLoc();
  if (Loc != NULL) {
    Ret_line = std::to_string(Loc->getLine());
    Ret_string = Loc->getFilename().str() + +":" + Ret_line + "," +
                 std::to_string(Loc->getColumn());
  } else {
    logPrintf(L3, "No debug info!!\n");
  }

  return make_pair(Ret_string, Ret_line);
}

std::pair<std::string, std::string>
FuzzIntrospector::getBBDebugInfo(BasicBlock *BB, DILocation *PrevLoc) {
  std::pair<std::string, std::string> Result = make_pair("", "");

  BasicBlock *CurrBB = BB;
  BranchInst *CurrBI;
  Instruction *CurrTI, *CurrI;
  DILocation *CurrLoc;

  // Traverse all dummy BBs associated with the previous Loc.
  do {
    CurrTI = CurrBB->getTerminator();
    CurrI = CurrBB->getFirstNonPHIOrDbgOrLifetime(true);
    if (CurrI == nullptr)
      break;
    CurrLoc = CurrI->getDebugLoc();
    CurrBI = dyn_cast<BranchInst>(CurrTI);
    if (CurrBI && !CurrBI->isConditional()) {
      CurrBB = CurrBI->getSuccessor(0);
    } else
      break;
  } while (CurrLoc == PrevLoc);

  // To skip the return BB in optimized CFG.
  if (dyn_cast<ReturnInst>(CurrTI)) {
    CurrI = BB->getFirstNonPHIOrDbgOrLifetime(true);
  }
  if (CurrI)
    Result = getInsnDebugInfo(CurrI);

  return Result;
}

void FuzzIntrospector::writeOutMap(std::vector<BranchProfileEntry> OutMap,
                                   std::string FileName) {
  std::error_code EC;
  logPrintf(L1, "Logging branchProfile to %s\n", FileName.c_str());

  auto YamlStream = std::make_unique<raw_fd_ostream>(
      FileName, EC, llvm::sys::fs::OpenFlags::OF_None);
  yaml::Output YamlOut(*YamlStream);

  YamlOut << OutMap;
}

// Return cyclomatic complexity of called functions in the BB
size_t FuzzIntrospector::calculateBBComplexity(BasicBlock *BB) {
  size_t CC = 0;

  for (auto &I : *BB) {
    // Skip debugging insns
    if (isa<DbgInfoIntrinsic>(&I)) {
      continue;
    }

    if (isa<CallInst>(I) || isa<InvokeInst>(I)) {
      Function *Callee;
      if (auto CI = dyn_cast<CallInst>(&I)) {
        Callee = value2Func(CI->getCalledOperand());
      } else if (auto II = dyn_cast<InvokeInst>(&I)) {
        Callee = value2Func(II->getCalledOperand());
      }
      if (FuncComplexityMap.find(Callee) != FuncComplexityMap.end()) {
        CC += FuncComplexityMap[Callee];
      }
    }
  }

  return CC;
}
