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
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.commons.lang3.StringUtils;
import ossf.fuzz.introspector.soot.yaml.BranchProfile;
import ossf.fuzz.introspector.soot.yaml.BranchSide;
import ossf.fuzz.introspector.soot.yaml.FunctionConfig;
import ossf.fuzz.introspector.soot.yaml.FunctionElement;
import ossf.fuzz.introspector.soot.yaml.FuzzerConfig;
import soot.Body;
import soot.PackManager;
import soot.Scene;
import soot.SceneTransformer;
import soot.SootClass;
import soot.SootMethod;
import soot.Transform;
import soot.Unit;
import soot.jimple.internal.JIfStmt;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import soot.options.Options;
import soot.toolkits.graph.Block;
import soot.toolkits.graph.BlockGraph;
import soot.toolkits.graph.BriefBlockGraph;

public class CallGraphGenerator {
  public static void main(String[] args) {
    System.out.println("[Callgraph] Running callgraph plugin");
    if (args.length < 3 || args.length > 4) {
      System.err.println("No jarFiles, entryClass or entryMethod.");
      return;
    }
    List<String> jarFiles = Arrays.asList(args[0].split(":"));
    String entryClass = args[1];
    String entryMethod = args[2];
    String excludePrefix = "";
    if (args.length == 4) {
      excludePrefix = args[3];
    }

    if (jarFiles.size() < 1) {
      System.err.println("Invalid jarFiles");
    }

    System.out.println("[Callgraph] Jar files used for analysis: " + jarFiles);

    soot.G.reset();

    // Add an custom analysis phase to Soot
    CustomSenceTransformer custom =
        new CustomSenceTransformer(entryClass, entryMethod, excludePrefix);
    PackManager.v().getPack("wjtp").add(new Transform("wjtp.custom", custom));

    // Set basic settings for the call graph generation
    Options.v().set_process_dir(jarFiles);
    Options.v().set_prepend_classpath(true);
    Options.v().set_src_prec(Options.src_prec_java);
    Options.v().set_include_all(true);
    Options.v().set_exclude(custom.getExcludeList());
    Options.v().set_no_bodies_for_excluded(true);
    Options.v().set_allow_phantom_refs(true);
    Options.v().set_whole_program(true);
    Options.v().set_keep_line_number(true);
    Options.v().set_no_writeout_body_releasing(true);

    // Load and set main class
    Options.v().set_main_class(entryClass);
    SootClass c = Scene.v().loadClass(entryClass, SootClass.BODIES);
    c.setApplicationClass();

    // Load and set custom entry point
    SootMethod entryPoint;
    try {
      entryPoint = c.getMethodByName(entryMethod);
    } catch (RuntimeException e) {
      System.out.println("Cannot find method: " + entryMethod + "from class: " + entryClass + ".");
      return;
    }
    List<SootMethod> entryPoints = new LinkedList<SootMethod>();
    entryPoints.add(entryPoint);
    Scene.v().setEntryPoints(entryPoints);

    // Load all related classes
    Scene.v().loadBasicClasses();
    Scene.v().loadNecessaryClasses();

    // Start the generation
    PackManager.v().runPacks();
  }
}

class CustomSenceTransformer extends SceneTransformer {
  private List<String> excludeList;
  private List<String> excludeMethodList;
  private List<Block> visitedBlock;
  private Map<String, Set<String>> edgeClassMap;
  private String entryClassStr;
  private String entryMethodStr;
  private SootMethod entryMethod;
  private FunctionConfig methodList;

  public CustomSenceTransformer(String entryClassStr, String entryMethodStr, String excludePrefix) {
    this.entryClassStr = entryClassStr;
    this.entryMethodStr = entryMethodStr;
    this.entryMethod = null;

    excludeList = new LinkedList<String>();

    for (String exclude : excludePrefix.split(":")) {
      if (!exclude.equals("")) {
        excludeList.add(exclude);
      }
    }

    excludeMethodList = new LinkedList<String>();

    excludeMethodList.add("<init>");
    excludeMethodList.add("<clinit>");
    excludeMethodList.add("finalize");

    edgeClassMap = new HashMap<String, Set<String>>();

    methodList = new FunctionConfig();
  }

  @Override
  protected void internalTransform(String phaseName, Map<String, String> options) {
    Map<SootClass, List<SootMethod>> classMethodMap = new HashMap<SootClass, List<SootMethod>>();
    methodList.setListName("All functions");

    System.out.println("[Callgraph] Internal transform init");
    // Extract Callgraph for the included Java Class
    System.out.println("[Callgraph] Determining classes to use for analysis.");
    CallGraph callGraph = Scene.v().getCallGraph();
    for (SootClass c : Scene.v().getApplicationClasses()) {
      if (!c.getName().startsWith("jdk")) {
        System.out.println("[Callgraph] [USE] class: " + c.getName());
        classMethodMap.put(c, c.getMethods());
      } else {
        System.out.println("[Callgraph] [SKIP] class: " + c.getName());
      }
    }
    System.out.println("[Callgraph] Finished going through classes");

    for (SootClass c : classMethodMap.keySet()) {
      System.out.println("Inspecting class: " + c.getName());
      // Loop through each methods in the class
      for (SootMethod m : classMethodMap.get(c)) {
        if (this.excludeMethodList.contains(m.getName())) {
          System.out.println("[Callgraph] Skipping method: " + m.getName());
          continue;
        }
        System.out.println("[Callgraph] Analysing method: " + m.getName());

        // Discover method related information
        FunctionElement element = new FunctionElement();
        Map<String, Integer> functionLineMap = new HashMap<String, Integer>();

        if (m.getName().equals(this.entryMethodStr) && c.getName().equals(this.entryClassStr)) {
          this.entryMethod = m;
          element.setFunctionName(m.getSubSignature().split(" ")[1]);
        } else {
          element.setFunctionName("[" + c.getFilePath() + "]." + m.getSubSignature().split(" ")[1]);
        }
        element.setFunctionSourceFile(c.getFilePath());
        element.setFunctionLinenumber(m.getJavaSourceStartLineNumber());
        element.setReturnType(m.getReturnType().toString());
        element.setFunctionDepth(0);
        element.setArgCount(m.getParameterCount());
        for (soot.Type type : m.getParameterTypes()) {
          element.addArgType(type.toString());
        }

        // Identify in / out edges of each method.
        int methodEdges = 0;
        Iterator<Edge> outEdges = this.mergePolymorphism(callGraph, callGraph.edgesOutOf(m));
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
              this.edgeClassMap.getOrDefault(
                  callerClass
                      + ":"
                      + tgt.getName()
                      + ":"
                      + ((edge.srcStmt() == null)
                          ? -1
                          : edge.srcStmt().getJavaSourceStartLineNumber()),
                  Collections.emptySet());
          className = this.mergeClassName(classNameSet);
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
              tgt.getSubSignature().split(" ")[1], edge.srcStmt().getJavaSourceStartLineNumber());
        }
        element.setEdgeCount(methodEdges);

        // Identify blocks information
        Body methodBody;
        try {
          methodBody = m.retrieveActiveBody();
        } catch (Exception e) {
          element.setBBCount(0);
          element.setiCount(0);
          element.setCyclomaticComplexity(0);
          methodList.addFunctionElement(element);
          // System.err.println("Source code for " + m + " not found.");
          continue;
        }
        BlockGraph blockGraph = new BriefBlockGraph(methodBody);

        element.setBBCount(blockGraph.size());
        int iCount = 0;
        for (Block block : blockGraph.getBlocks()) {
          Iterator<Unit> blockIt = block.iterator();
          while (blockIt.hasNext()) {
            Unit unit = blockIt.next();
            if (unit instanceof JIfStmt) {
              // Handle branch profile
              BranchProfile branchProfile = new BranchProfile();

              Map<String, Integer> trueBlockLine =
                  getBlockStartEndLineWithLineNumber(
                      blockGraph.getBlocks(), unit.getJavaSourceStartLineNumber() + 1);
              Map<String, Integer> falseBlockLine =
                  getBlockStartEndLineWithLineNumber(
                      blockGraph.getBlocks(),
                      ((JIfStmt) unit)
                          .getUnitBoxes()
                          .get(0)
                          .getUnit()
                          .getJavaSourceStartLineNumber());

              // True branch
              if (!trueBlockLine.isEmpty()) {
                Integer start = trueBlockLine.get("start");
                Integer end = trueBlockLine.get("end");
                BranchSide branchSide = new BranchSide();
                branchSide.setBranchSideStr(c.getName() + ":" + start);
                branchSide.setBranchSideFuncs(
                    getFunctionCallInTargetLine(functionLineMap, start, end));
                branchProfile.addBranchSides(branchSide);
              }

              // False branch
              if (!falseBlockLine.isEmpty()) {
                Integer start = falseBlockLine.get("start");
                Integer end = falseBlockLine.get("end");
                BranchSide branchSide = new BranchSide();
                branchSide.setBranchSideStr(c.getName() + ":" + (start - 1));
                branchSide.setBranchSideFuncs(
                    getFunctionCallInTargetLine(functionLineMap, start, end));
                branchProfile.addBranchSides(branchSide);
              }

              branchProfile.setBranchString(
                  c.getName() + ":" + unit.getJavaSourceStartLineNumber());
              element.addBranchProfile(branchProfile);
            }
            iCount++;
          }
        }
        element.setiCount(iCount);

        visitedBlock = new LinkedList<Block>();
        visitedBlock.addAll(blockGraph.getTails());
        element.setCyclomaticComplexity(calculateCyclomaticComplexity(blockGraph.getHeads(), 0));

        methodList.addFunctionElement(element);
      }
    }
    try {
      if (methodList.getFunctionElements().size() == 0) {
        throw new RuntimeException(
            "No method in analysing scope, consider relaxing the exclude constraint.");
      }

      // Extract call tree and write to .data
      File file = new File("fuzzerLogFile-" + this.entryClassStr + ".data");
      file.createNewFile();
      FileWriter fw = new FileWriter(file);
      fw.write(extractCallTree(callGraph, this.entryMethod, 0, -1));
      fw.close();

      // Calculate function depth
      this.calculateDepth();

      // Extract other info and write to .data.yaml
      ObjectMapper om = new ObjectMapper(new YAMLFactory());
      file = new File("fuzzerLogFile-" + this.entryClassStr + ".data.yaml");
      file.createNewFile();
      fw = new FileWriter(file);
      FuzzerConfig config = new FuzzerConfig();
      config.setFilename(this.entryClassStr);
      config.setFunctionConfig(methodList);
      fw.write(om.writeValueAsString(config));
      fw.close();
    } catch (IOException e) {
      System.err.println(e);
    }
  }

  // Include empty profile with name for excluded standard libraries
  private void handleExcludedMethod(CallGraph cg, String cName, String mName, SootMethod m) {
    for (String name : cName.split(":")) {
      for (String prefix : this.excludeList) {
        if (name.startsWith(prefix)) {
          FunctionElement element = new FunctionElement();
          element.setFunctionName("[" + name + "]." + mName);
          element.setFunctionSourceFile(name);
          element.setFunctionLinenumber(m.getJavaSourceStartLineNumber());
          element.setReturnType(m.getReturnType().toString());
          element.setFunctionDepth(0);
          element.setArgCount(m.getParameterCount());
          for (soot.Type type : m.getParameterTypes()) {
            element.addArgType(type.toString());
          }
          Iterator<Edge> inEdges = cg.edgesInto(m);
          Integer counter = 0;
          while (inEdges.hasNext()) {
            counter++;
            inEdges.next();
          }
          element.setFunctionUses(counter);
          element.setEdgeCount(0);
          element.setBBCount(0);
          element.setiCount(0);
          element.setCyclomaticComplexity(0);
          methodList.addFunctionElement(element);
        }
      }
    }
  }

  private FunctionElement searchElement(String functionName) {
    for (FunctionElement element : methodList.getFunctionElements()) {
      if (element.getFunctionName().equals(functionName)) {
        return element;
      }
    }
    return null;
  }

  // Shorthand for calculateDepth from Top
  private void calculateDepth() {
    for (FunctionElement element : methodList.getFunctionElements()) {
      element.setFunctionDepth(this.calculateDepth(element));
    }
  }

  // Calculate method depth
  private Integer calculateDepth(FunctionElement element) {
    Integer depth = element.getFunctionDepth();

    if (depth > 0) {
      return depth;
    }

    for (String reachedName : element.getFunctionsReached()) {
      FunctionElement reachedElement = this.searchElement(reachedName);
      if (reachedElement != null) {
        Integer newDepth = this.calculateDepth(reachedElement) + 1;
        depth = (newDepth > depth) ? newDepth : depth;
      }
    }

    return depth;
  }

  // Shorthand for extractCallTree from top
  private String extractCallTree(CallGraph cg, SootMethod method, Integer depth, Integer line) {
    return "Call tree\n"
        + extractCallTree(cg, method, depth, line, new LinkedList<SootMethod>(), null);
  }

  // Recursively extract calltree from stored method relationship, ignoring loops
  private String extractCallTree(
      CallGraph cg,
      SootMethod method,
      Integer depth,
      Integer line,
      List<SootMethod> handled,
      String callerClass) {
    StringBuilder callTree = new StringBuilder();

    if (this.excludeMethodList.contains(method.getName())) {
      return "";
    }

    String className = "";
    if (callerClass != null) {
      Set<String> classNameSet =
          this.edgeClassMap.getOrDefault(
              callerClass + ":" + method.getName() + ":" + line, Collections.emptySet());
      className = this.mergeClassName(classNameSet);
      boolean merged = false;
      for (String name : className.split(":")) {
        if (name.equals(method.getDeclaringClass().getName())) {
          merged = true;
          break;
        }
      }
      if (!merged) {
        className = method.getDeclaringClass().getName();
      }
    } else {
      className = method.getDeclaringClass().getName();
    }

    String methodName = method.getSubSignature().split(" ")[1];
    callTree.append(StringUtils.leftPad("", depth * 2));
    callTree.append(methodName + " " + className + " linenumber=" + line + "\n");

    boolean excluded = false;
    checkExclusionLoop:
    for (String cl : className.split(":")) {
      for (String prefix : this.excludeList) {
        if (cl.startsWith(prefix)) {
          excluded = true;
          break checkExclusionLoop;
        }
      }
    }
    if (excluded) {
      this.handleExcludedMethod(cg, className, methodName, method);
      return callTree.toString();
    }

    if (!handled.contains(method)) {
      handled.add(method);
      Iterator<Edge> outEdges = this.mergePolymorphism(cg, cg.edgesOutOf(method));

      while (outEdges.hasNext()) {
        Edge edge = outEdges.next();
        SootMethod tgt = edge.tgt();

        if (tgt.equals(edge.src())) {
          continue;
        }

        callTree.append(
            extractCallTree(
                cg,
                tgt,
                depth + 1,
                (edge.srcStmt() == null) ? -1 : edge.srcStmt().getJavaSourceStartLineNumber(),
                handled,
                edge.src().getDeclaringClass().getName()));
      }
    }

    return callTree.toString();
  }

  private Integer calculateCyclomaticComplexity(List<Block> start, Integer complexity) {
    for (Block block : start) {
      if (visitedBlock.contains(block)) {
        complexity += 1;
      } else {
        visitedBlock.add(block);
        complexity = calculateCyclomaticComplexity(block.getSuccs(), complexity);
      }
    }
    return complexity;
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

  private Iterator<Edge> sortEdgeByLineNumber(Iterator<Edge> it) {
    List<Edge> edgeList = new LinkedList<Edge>();

    while (it.hasNext()) {
      edgeList.add(it.next());
    }

    Collections.sort(
        edgeList,
        new Comparator<Edge>() {
          @Override
          public int compare(Edge e1, Edge e2) {
            int line =
                e1.srcStmt().getJavaSourceStartLineNumber()
                    - e2.srcStmt().getJavaSourceStartLineNumber();
            if (line == 0) {
              return e1.tgt()
                  .getDeclaringClass()
                  .getName()
                  .compareTo(e2.tgt().getDeclaringClass().getName());
            } else {
              return line;
            }
          }
        });

    return edgeList.iterator();
  }

  private Iterator<Edge> mergePolymorphism(CallGraph cg, Iterator<Edge> it) {
    List<Edge> edgeList = new LinkedList<Edge>();

    it = this.sortEdgeByLineNumber(it);

    while (it.hasNext()) {
      Edge edge = it.next();
      String className = edge.tgt().getDeclaringClass().getName();
      String matchStr =
          edge.src().getDeclaringClass().getName()
              + ":"
              + edge.tgt().getName()
              + ":"
              + edge.srcStmt().getJavaSourceStartLineNumber();

      if (cg.edgesOutOf(edge.tgt()).hasNext()) {
        edgeList.add(edge);
      } else {
        Set<String> classNameSet;
        if (this.edgeClassMap.containsKey(matchStr)) {
          classNameSet = this.edgeClassMap.get(matchStr);
        } else {
          classNameSet = new HashSet<String>();
          edgeList.add(edge);
        }
        classNameSet.add(className);
        this.edgeClassMap.put(matchStr, classNameSet);
      }
    }

    List<String> keySet = new LinkedList<String>();
    for (String key : this.edgeClassMap.keySet()) {
      if (this.edgeClassMap.get(key).size() <= 1) {
        keySet.add(key);
      }
    }
    for (String key : keySet) {
      this.edgeClassMap.remove(key);
    }

    return this.sortEdgeByLineNumber(edgeList.iterator());
  }

  private String mergeClassName(Set<String> classNameSet) {
    StringBuilder mergedClassName = new StringBuilder();

    List<String> classNameList = new LinkedList<String>(classNameSet);
    Collections.sort(classNameList);

    for (String className : classNameList) {
      if (mergedClassName.length() > 0) {
        mergedClassName.append(":");
      }
      mergedClassName.append(className);
    }

    return mergedClassName.toString();
  }

  public List<String> getExcludeList() {
    return excludeList;
  }
}
