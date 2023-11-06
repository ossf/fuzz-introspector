// Copyright 2022 Fuzz Introspector Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
///////////////////////////////////////////////////////////////////////////

package ossf.fuzz.introspector.soot;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import ossf.fuzz.introspector.soot.utils.CalculationUtils;
import ossf.fuzz.introspector.soot.utils.CalltreeUtils;
import ossf.fuzz.introspector.soot.utils.MergeUtils;
import ossf.fuzz.introspector.soot.yaml.BranchProfile;
import ossf.fuzz.introspector.soot.yaml.BranchSide;
import ossf.fuzz.introspector.soot.yaml.Callsite;
import ossf.fuzz.introspector.soot.yaml.FunctionConfig;
import ossf.fuzz.introspector.soot.yaml.FunctionElement;
import ossf.fuzz.introspector.soot.yaml.FuzzerConfig;
import soot.Body;
import soot.ResolutionFailedException;
import soot.Scene;
import soot.SceneTransformer;
import soot.SootClass;
import soot.SootMethod;
import soot.Unit;
import soot.Value;
import soot.ValueBox;
import soot.jimple.AndExpr;
import soot.jimple.IfStmt;
import soot.jimple.InvokeExpr;
import soot.jimple.OrExpr;
import soot.jimple.Stmt;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import soot.toolkits.graph.Block;
import soot.toolkits.graph.BlockGraph;
import soot.toolkits.graph.BriefBlockGraph;

public class SootSceneTransformer extends SceneTransformer {
  private List<String> targetPackageList;
  private List<String> includeList;
  private List<String> excludeList;
  private List<String> excludeMethodList;
  private List<String> projectClassList;
  private List<SootMethod> reachedSinkMethodList;
  private List<FunctionElement> depthHandled;
  private Map<String, Set<String>> edgeClassMap;
  private Map<String, Set<String>> sinkMethodMap;
  private String entryClassStr;
  private String entryMethodStr;
  private SootMethod entryMethod;
  private FunctionConfig methodList;
  private Boolean isAutoFuzz;
  private Boolean analyseFinished;

  public SootSceneTransformer(
      String entryClassStr,
      String entryMethodStr,
      String targetPackagePrefix,
      String excludeMethodStr,
      String includePrefix,
      String excludePrefix,
      String sinkMethod,
      String sourceDirectory,
      Boolean isAutoFuzz) {
    this.entryClassStr = entryClassStr;
    this.entryMethodStr = entryMethodStr;
    this.isAutoFuzz = isAutoFuzz;
    this.entryMethod = null;

    targetPackageList = new LinkedList<String>();
    includeList = new LinkedList<String>();
    excludeList = new LinkedList<String>();
    excludeMethodList = new LinkedList<String>();
    projectClassList = new LinkedList<String>();
    reachedSinkMethodList = new LinkedList<SootMethod>();
    edgeClassMap = new HashMap<String, Set<String>>();
    sinkMethodMap = new HashMap<String, Set<String>>();
    methodList = new FunctionConfig();
    analyseFinished = false;

    if (!targetPackagePrefix.equals("ALL")) {
      for (String targetPackage : targetPackagePrefix.split(":")) {
        if (!targetPackage.equals("")) {
          targetPackageList.add(targetPackage);
        }
      }
    }

    if ((!sourceDirectory.equals("")) && (!sourceDirectory.equals("NULL"))) {
      try (Stream<Path> walk = Files.walk(Paths.get(sourceDirectory))) {
        List<String> sourceList =
            walk.map(x -> x.toString())
                .filter(f -> f.endsWith(".java"))
                .collect(Collectors.toList());
        for (String source : sourceList) {
          projectClassList.add(source.substring(source.lastIndexOf("/") + 1).replace(".java", ""));
        }
      } catch (IOException e) {
        // Fail to retrieve project class list, ignore the list.
        projectClassList = new LinkedList<String>();
      }
    }

    for (String include : includePrefix.split(":")) {
      if (!include.equals("")) {
        includeList.add(include);
      }
    }
    includeList.add(entryClassStr);

    if (projectClassList.size() == 0) {
      for (String exclude : excludePrefix.split(":")) {
        if (!exclude.equals("")) {
          excludeList.add(exclude);
        }
      }
    }

    for (String exclude : excludeMethodStr.split(":")) {
      excludeMethodList.add(exclude);
    }

    sinkMethodMap = new HashMap<String, Set<String>>();
    for (String sink : sinkMethod.split(":")) {
      if (!sink.equals("")) {
        String className = sink.split("].")[0].substring(1);
        String methodName = sink.split("].")[1];
        Set<String> set =
            new HashSet<String>(this.sinkMethodMap.getOrDefault(className, new HashSet<String>()));
        set.add(methodName);
        sinkMethodMap.put(className, set);
      }
    }
  }

  @Override
  protected void internalTransform(String phaseName, Map<String, String> options) {
    Map<SootClass, List<SootMethod>> classMethodMap = new HashMap<SootClass, List<SootMethod>>();
    methodList.setListName("All functions");

    System.out.println("[Callgraph] Internal transform init");
    // Extract Callgraph for the included Java Class
    System.out.println("[Callgraph] Determining classes to use for analysis.");
    CallGraph callGraph = Scene.v().getCallGraph();
    Iterator<SootClass> classIterator = Scene.v().getClasses().snapshotIterator();
    while (classIterator.hasNext()) {
      boolean isInclude = false;
      boolean isIgnore = false;
      boolean isSinkClass = false;
      boolean isAutoFuzzIgnore = false;
      SootClass c = classIterator.next();
      String cname = c.getName();

      // Check for a list of classes of prefixes that must handled
      for (String prefix : includeList) {
        if (cname.startsWith(prefix.replace("*", ""))) {
          isInclude = true;
          break;
        }
      }

      // Check if remaining classes are in the exclude list
      // Or if it is a class contains sink method
      // If the class is in the exclude list and are not classes
      // that contains sink method, ignore it
      if (!isInclude) {
        for (String prefix : excludeList) {
          if (cname.startsWith(prefix.replace("*", ""))) {
            if (this.sinkMethodMap.containsKey(cname)) {
              isSinkClass = true;
            } else {
              isIgnore = true;
            }
            break;
          }
        }
      }

      // Check if the remaining classes have a prefix of one
      // of the target package or if it can be found in the
      // project source directory if provided.
      // If target package prefix has been specified and the
      // class is not in those package, ignore it
      // If project source directory has been specified and
      // the class is not exists in the project source
      // directory, ignore it
      if (!isIgnore && !isSinkClass && !isInclude) {
        if (this.hasTargetPackage()) {
          boolean targetPackage = false;
          for (String prefix : targetPackageList) {
            if (cname.startsWith(prefix.replace("*", ""))) {
              targetPackage = true;
              break;
            }
          }
          if (!targetPackage) {
            isIgnore = true;
          }
        } else {
          String currClassName = cname.substring(cname.lastIndexOf(".") + 1).split("\\$")[0];
          if ((projectClassList.size() > 0) && (!projectClassList.contains(currClassName))) {
            isIgnore = true;
          }
        }
      }

      if (!c.isConcrete() || c.isPhantom()) {
        isIgnore = true;
        isAutoFuzzIgnore = true;
      }

      if (isAutoFuzz) {
        if (c.getName().endsWith("Exception")
            || c.getName().endsWith("Error")
            || c.getName().contains("$")
            || !c.isPublic()) {
          isIgnore = true;
          isAutoFuzzIgnore = true;
        }
      }

      if (!isIgnore) {
        //        System.out.println("[Callgraph] [USE] class: " + cname);
        List<SootMethod> mList = new LinkedList<SootMethod>();

        if (isSinkClass) {
          for (SootMethod method : c.getMethods()) {
            Set<String> sinkMethodNameSet = this.sinkMethodMap.get(cname);
            if (sinkMethodNameSet.contains(method.getName())) {
              mList.add(method);
            }
          }
        } else {
          mList.addAll(c.getMethods());
        }

        classMethodMap.put(c, mList);
      } else {
        //        System.out.println("[Callgraph] [SKIP] class: " + cname);
      }
      if (isAutoFuzz && !isAutoFuzzIgnore) {
        CalltreeUtils.addConstructors(this.methodList, c);
      }
    }
    System.out.println("[Callgraph] Finished going through classes");

    for (SootClass c : classMethodMap.keySet()) {
      System.out.println("Inspecting class: " + c.getName());
      // Loop through each methods in the class
      boolean isSinkClass = this.sinkMethodMap.containsKey(c.getName());
      List<SootMethod> mList = new LinkedList<SootMethod>();
      mList.addAll(classMethodMap.get(c));
      for (SootMethod m : mList) {
        if (this.excludeMethodList.contains(m.getName())) {
          // System.out.println("[Callgraph] Skipping method: " + m.getName());
          continue;
        }
        if (isSinkClass) {
          // System.out.println("[Callgraph] Skipping sink method: " + m.getName());
          continue;
        }
        // System.out.println("[Callgraph] Analysing method: " + m.getName());

        // Discover method related information
        FunctionElement element = new FunctionElement();
        Map<String, Integer> functionLineMap = new HashMap<String, Integer>();

        if (m.getName().equals(this.entryMethodStr) && c.getName().equals(this.entryClassStr)) {
          this.entryMethod = m;
        }

        element.setFunctionName("[" + c.getFilePath() + "]." + m.getSubSignature().split(" ")[1]);
        element.setBaseInformation(m);
        if (isAutoFuzz) {
          element.setJavaMethodInfo(m);
        }

        // Identify in / out edges of each method.
        int methodEdges = 0;
        Iterator<Edge> outEdges =
            MergeUtils.mergePolymorphism(
                callGraph,
                callGraph.edgesOutOf(m),
                this.excludeList,
                this.getIncludeList(),
                this.edgeClassMap);
        Iterator<Edge> inEdges = callGraph.edgesInto(m);
        while (inEdges.hasNext()) {
          methodEdges++;
          inEdges.next();
        }
        element.setFunctionUses(methodEdges);
        methodEdges = 0;
        for (; outEdges.hasNext(); methodEdges++) {
          Edge edge = outEdges.next();
          SootMethod tgt = edge.tgt();
          if (this.excludeMethodList.contains(tgt.getName())) {
            methodEdges--;
            continue;
          }
          String callerClass = edge.src().getDeclaringClass().getName();
          String className = "";
          Set<String> classNameSet =
              new HashSet<String>(
                  this.edgeClassMap.getOrDefault(
                      callerClass
                          + ":"
                          + tgt.getName()
                          + ":"
                          + ((edge.srcStmt() == null)
                              ? -1
                              : edge.srcStmt().getJavaSourceStartLineNumber()),
                      Collections.emptySet()));
          className = MergeUtils.mergeClassName(classNameSet);
          boolean merged = false;
          for (String name : className.split(":")) {
            if (name.equals(tgt.getDeclaringClass().getName())) {
              merged = true;
              break;
            }
          }
          if (!merged) {
            className = tgt.getDeclaringClass().getName();
          }
          element.addFunctionsReached("[" + className + "]." + tgt.getSubSignature().split(" ")[1]);
          functionLineMap.put(
              tgt.getSubSignature().split(" ")[1],
              (edge.srcStmt() == null) ? -1 : edge.srcStmt().getJavaSourceStartLineNumber());
        }
        element.setEdgeCount(methodEdges);

        // Identify blocks information
        Body methodBody;
        try {
          methodBody = m.retrieveActiveBody();
        } catch (Exception e) {
          this.methodList.addFunctionElement(element);
          // System.err.println("Source code for " + m + " not found.");
          continue;
        }
        BlockGraph blockGraph = new BriefBlockGraph(methodBody);

        int iCount = 0;
        for (Block block : blockGraph.getBlocks()) {
          Iterator<Unit> blockIt = block.iterator();
          while (blockIt.hasNext()) {
            // Looping statement from all blocks from this specific method.
            Unit unit = blockIt.next();
            if (unit instanceof Stmt) {
              Callsite callsite =
                  handleMethodInvocationInStatement((Stmt) unit, c.getFilePath(), isAutoFuzz);
              if (callsite != null) {
                element.addCallsite(callsite);
              }
              if (unit instanceof IfStmt) {
                element.addBranchProfile(
                    handleIfStatement(blockGraph.getBlocks(), unit, c.getName(), functionLineMap));
              }
            }
            iCount++;
          }
        }

        element.setCountInformation(
            blockGraph.size(), iCount, CalculationUtils.calculateCyclomaticComplexity(blockGraph));

        this.methodList.addFunctionElement(element);
      }
    }
    try {
      if (methodList.getFunctionElements().size() == 0) {
        throw new RuntimeException(
            "No method in analysing scope, consider relaxing the exclude constraint.");
      }

      CalculationUtils.calculateAllCallDepth(this.methodList);
      if (!isAutoFuzz) {
        CalltreeUtils.addSinkMethods(this.methodList, this.reachedSinkMethodList, this.isAutoFuzz);
      }

      // Extract call tree and write to .data
      System.out.println("Generating fuzzerLogFile-" + this.entryClassStr + ".data");
      File file = new File("fuzzerLogFile-" + this.entryClassStr + ".data");
      file.createNewFile();
      FileWriter fw = new FileWriter(file);
      this.edgeClassMap = new HashMap<String, Set<String>>();
      CalltreeUtils.setBaseData(
          this.includeList,
          this.excludeList,
          this.excludeMethodList,
          this.edgeClassMap,
          this.sinkMethodMap);
      CalltreeUtils.extractCallTree(fw, callGraph, this.entryMethod, 0, -1);
      fw.close();

      // Extract other info and write to .data.yaml
      System.out.println("Generating fuzzerLogFile-" + this.entryClassStr + ".data.yaml");
      ObjectMapper om = new ObjectMapper(new YAMLFactory());
      file = new File("fuzzerLogFile-" + this.entryClassStr + ".data.yaml");
      file.createNewFile();
      fw = new FileWriter(file);
      FuzzerConfig config = new FuzzerConfig();
      config.setFilename(this.entryClassStr);
      config.setEntryMethod(this.entryMethodStr);
      config.setFunctionConfig(methodList);
      fw.write(om.writeValueAsString(config));
      fw.close();
    } catch (IOException e) {
      System.err.println(e);
    }
    System.out.println("Finish processing for fuzzer: " + this.entryClassStr);
    analyseFinished = true;
  }

  private Map<String, Integer> getBlockStartEndLineWithLineNumber(
      List<Block> blocks, Integer lineNumber) {
    Integer startLine;
    Integer endLine;

    for (Block block : blocks) {
      Iterator<Unit> it = block.iterator();
      startLine = -1;
      endLine = -1;
      while (it.hasNext()) {
        Unit unit = it.next();
        if (startLine == -1) {
          startLine = unit.getJavaSourceStartLineNumber();
        }
        endLine = unit.getJavaSourceStartLineNumber();
      }
      if (lineNumber >= startLine && lineNumber <= endLine) {
        Map<String, Integer> line = new HashMap<String, Integer>();
        line.put("start", startLine);
        line.put("end", endLine);
        return line;
      }
    }

    return Collections.emptyMap();
  }

  private List<String> getFunctionCallInTargetLine(
      Map<String, Integer> functionLineMap, Integer startLine, Integer endLine) {
    List<String> targetFunctionList = new LinkedList<String>();

    for (String key : functionLineMap.keySet()) {
      Integer lineNumber = functionLineMap.get(key);
      if (lineNumber >= startLine && lineNumber <= endLine) {
        targetFunctionList.add(key);
      }
    }

    return targetFunctionList;
  }

  /**
   * The method retrieves the invocation body of a statement if existed. Then it determines the
   * information of the method invoked and stores them in the result to record the callsite
   * information of the invoked method in its parent method.
   *
   * @param stmt the statement to handle
   * @param sourceFilePath the file path for the parent method
   * @return the callsite object to store in the output yaml file, return null if Soot fails to
   *     resolve the invocation
   */
  private Callsite handleMethodInvocationInStatement(
      Stmt stmt, String sourceFilePath, Boolean isAutoFuzz) {
    // Handle statements of a method
    try {
      if ((stmt.containsInvokeExpr()) && (sourceFilePath != null)) {
        InvokeExpr expr = stmt.getInvokeExpr();
        Callsite callsite = new Callsite();
        SootMethod target = expr.getMethod();
        SootClass tClass = target.getDeclaringClass();
        Set<String> sink =
            this.sinkMethodMap.getOrDefault(tClass.getName(), Collections.emptySet());
        if (sink.contains(target.getName())) {
          this.reachedSinkMethodList.add(target);
        }
        if (!this.excludeMethodList.contains(target.getName())) {
          callsite.setSource(sourceFilePath + ":" + stmt.getJavaSourceStartLineNumber() + ",1");
          if (isAutoFuzz) {
            callsite.setMethodName(
                "[" + tClass.getName() + "]." + target.getSubSignature().split(" ")[1]);
          } else {
            callsite.setMethodName("[" + tClass.getName() + "]." + target.getName());
          }
          return callsite;
        }
      }
    } catch (ResolutionFailedException e) {
      // Some project may invoke method in a non-traditional way, for example
      // invoking class static method within an object instance of that class.
      // These invocation could cause ResolutionFailedException and they are skipped
      // as the normal static invocation is handled in other location. So do nothing here.
    }

    return null;
  }

  private BranchProfile handleIfStatement(
      List<Block> blocks, Unit unit, String cname, Map<String, Integer> functionLineMap) {
    // Handle if branch
    BranchProfile branchProfile = new BranchProfile();

    Integer trueBlockLineNumber = unit.getJavaSourceStartLineNumber() + 1;
    Integer falseBlockLineNumber =
        ((IfStmt) unit).getUnitBoxes().get(0).getUnit().getJavaSourceStartLineNumber();

    Map<String, Integer> trueBlockLine =
        getBlockStartEndLineWithLineNumber(blocks, trueBlockLineNumber);
    Map<String, Integer> falseBlockLine =
        getBlockStartEndLineWithLineNumber(blocks, falseBlockLineNumber);

    // True branch
    if (!trueBlockLine.isEmpty()) {
      Integer start = falseBlockLine.get("start");
      branchProfile.addBranchSides(
          processBranch(trueBlockLine, cname + ":" + start, functionLineMap));
    }

    // False branch
    if (!falseBlockLine.isEmpty()) {
      Integer start = falseBlockLine.get("start");
      branchProfile.addBranchSides(
          processBranch(falseBlockLine, cname + ":" + (start - 1), functionLineMap));
    }

    branchProfile.setBranchString(cname + ":" + unit.getJavaSourceStartLineNumber());

    return branchProfile;
  }

  private BranchSide processBranch(
      Map<String, Integer> blockLine, String cname, Map<String, Integer> functionLineMap) {
    BranchSide branchSide = new BranchSide();

    Integer start = blockLine.get("start");
    Integer end = blockLine.get("end");
    branchSide.setBranchSideStr(cname);
    branchSide.setBranchSideFuncs(getFunctionCallInTargetLine(functionLineMap, start, end));

    return branchSide;
  }

  public Boolean hasTargetPackage() {
    return (targetPackageList.size() > 0);
  }

  public List<String> getIncludeList() {
    List<String> output = new LinkedList<String>(this.includeList);
    output.addAll(this.sinkMethodMap.keySet());
    return output;
  }

  public List<String> getExcludeList() {
    return excludeList;
  }

  public Boolean isAnalyseFinished() {
    return this.analyseFinished;
  }

  public void setEntryMethodStr(String entryMethodStr) {
    this.entryMethodStr = entryMethodStr;
  }
}
