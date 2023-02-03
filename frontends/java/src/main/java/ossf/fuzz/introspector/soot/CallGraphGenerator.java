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
import ossf.fuzz.introspector.soot.yaml.Callsite;
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
import soot.Value;
import soot.ValueBox;
import soot.jimple.AndExpr;
import soot.jimple.GotoStmt;
import soot.jimple.IfStmt;
import soot.jimple.InvokeExpr;
import soot.jimple.LookupSwitchStmt;
import soot.jimple.OrExpr;
import soot.jimple.ReturnStmt;
import soot.jimple.ReturnVoidStmt;
import soot.jimple.Stmt;
import soot.jimple.ThrowStmt;
import soot.jimple.toolkits.annotation.logic.LoopFinder;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import soot.options.Options;
import soot.toolkits.graph.Block;
import soot.toolkits.graph.BlockGraph;
import soot.toolkits.graph.BriefBlockGraph;
import soot.toolkits.graph.BriefUnitGraph;
import soot.toolkits.graph.UnitGraph;

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
    String includePrefix = "";
    String excludePrefix = "";
    String sinkMethod = "";
    if (args.length == 4) {
      includePrefix = args[3].split("===")[0];
      excludePrefix = args[3].split("===")[1];
      sinkMethod = args[3].split("===")[2];
    }

    if (jarFiles.size() < 1) {
      System.err.println("Invalid jarFiles");
    }

    System.out.println("[Callgraph] Jar files used for analysis: " + jarFiles);

    soot.G.reset();

    // Add an custom analysis phase to Soot
    CustomSenceTransformer custom =
        new CustomSenceTransformer(
            entryClass, entryMethod, includePrefix, excludePrefix, sinkMethod);
    PackManager.v().getPack("wjtp").add(new Transform("wjtp.custom", custom));

    // Set basic settings for the call graph generation
    Options.v().set_process_dir(jarFiles);
    Options.v().set_prepend_classpath(true);
    Options.v().set_src_prec(Options.src_prec_java);
    Options.v().set_include(custom.getIncludeList());
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
    Scene.v().loadNecessaryClasses();
    Scene.v().loadDynamicClasses();

    // Start the generation
    PackManager.v().runPacks();
  }
}

class CustomSenceTransformer extends SceneTransformer {
  private List<String> includeList;
  private List<String> excludeList;
  private List<String> excludeMethodList;
  private Map<String, Set<String>> edgeClassMap;
  private Map<String, Set<String>> sinkMethodMap;
  private String entryClassStr;
  private String entryMethodStr;
  private SootMethod entryMethod;
  private FunctionConfig methodList;

  public CustomSenceTransformer(
      String entryClassStr,
      String entryMethodStr,
      String includePrefix,
      String excludePrefix,
      String sinkMethod) {
    this.entryClassStr = entryClassStr;
    this.entryMethodStr = entryMethodStr;
    this.entryMethod = null;

    includeList = new LinkedList<String>();
    excludeList = new LinkedList<String>();

    for (String include : includePrefix.split(":")) {
      if (!include.equals("")) {
        includeList.add(include);
      }
    }
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
      boolean isSink = false;
      SootClass c = classIterator.next();
      String cname = c.getName();

      for (String prefix : includeList) {
        if (cname.startsWith(prefix)) {
          isInclude = true;
          break;
        }
      }
      if (!isInclude) {
        for (String prefix : excludeList) {
          if (cname.startsWith(prefix)) {
            if (sinkMethodMap.containsKey(cname)) {
              isSink = true;
            }
            isIgnore = true;
            break;
          }
        }
      }

      if (!isIgnore || isSink) {
        System.out.println("[Callgraph] [USE] class: " + cname);
        List<SootMethod> methodList = new LinkedList<SootMethod>();
        methodList.addAll(c.getMethods());

        if (isSink) {
          List<SootMethod> sinkList = new LinkedList<SootMethod>();
          for (SootMethod m : methodList) {
            if (sinkMethodMap.get(cname).contains(m.getName())) {
              sinkList.add(m);
            }
          }
          classMethodMap.put(c, sinkList);
        } else {
          classMethodMap.put(c, methodList);
        }
      } else {
        System.out.println("[Callgraph] [SKIP] class: " + cname);
      }
    }
    System.out.println("[Callgraph] Finished going through classes");

    for (SootClass c : classMethodMap.keySet()) {
      System.out.println("Inspecting class: " + c.getName());
      // Loop through each methods in the class
      List<SootMethod> mList = new LinkedList<SootMethod>();
      mList.addAll(classMethodMap.get(c));
      for (SootMethod m : mList) {
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
        }

        element.setFunctionName("[" + c.getFilePath() + "]." + m.getSubSignature().split(" ")[1]);
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
          // Source code not provided for this method.
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
            // Looping statement from all blocks from this specific method.
            Unit unit = blockIt.next();
            if (unit instanceof Stmt) {
              Callsite callsite = handleMethodInvocationInStatement((Stmt) unit, c.getFilePath());
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
        element.setiCount(iCount);

        // Calculate method cyclomatic complexity from method unit graph
        UnitGraph unitGraph = new BriefUnitGraph(methodBody);
        element.setCyclomaticComplexity(calculateCyclomaticComplexity(unitGraph));

        methodList.addFunctionElement(element);
      }
    }
    try {
      if (methodList.getFunctionElements().size() == 0) {
        throw new RuntimeException(
            "No method in analysing scope, consider relaxing the exclude constraint.");
      }

      // Extract call tree and write to .data
      System.out.println("Generating fuzzerLogFile-" + this.entryClassStr + ".data");
      File file = new File("fuzzerLogFile-" + this.entryClassStr + ".data");
      file.createNewFile();
      FileWriter fw = new FileWriter(file);
      fw.write(extractCallTree(callGraph, this.entryMethod, 0, -1));
      fw.close();

      // Calculate function depth
      // this.calculateDepth();

      // Extract other info and write to .data.yaml
      System.out.println("Generating fuzzerLogFile-" + this.entryClassStr + ".data.yaml");
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
      element.setFunctionDepth(this.calculateDepth(element, new HashSet<FunctionElement>()));
    }
  }

  // Calculate method depth
  private Integer calculateDepth(FunctionElement element, Set<FunctionElement> handled) {
    Integer depth = element.getFunctionDepth();

    if ((depth > 0) || (handled.contains(element))) {
      return depth;
    }

    handled.add(element);

    for (String reachedName : element.getFunctionsReached()) {
      FunctionElement reachedElement = this.searchElement(reachedName);
      if (reachedElement != null) {
        Integer newDepth = this.calculateDepth(reachedElement, handled) + 1;
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
          new HashSet<String>(
              this.edgeClassMap.getOrDefault(
                  callerClass + ":" + method.getName() + ":" + line, Collections.emptySet()));
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
    boolean sink = false;
    checkExclusionLoop:
    for (String cl : className.split(":")) {
      for (String prefix : this.excludeList) {
        if (cl.startsWith(prefix)) {
          if (sinkMethodMap.getOrDefault(cl, Collections.emptySet()).contains(method.getName())) {
            sink = true;
          }
          excluded = true;
          break checkExclusionLoop;
        }
      }
    }
    if (excluded) {
      this.handleExcludedMethod(cg, method.getDeclaringClass().getName(), methodName, method);
      if (sink) {
        return callTree.toString();
      } else {
        return "";
      }
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

  private Integer calculateCyclomaticComplexity(UnitGraph unitGraph) {
    Integer complexity = 1;

    Iterator<Unit> it = unitGraph.iterator();
    if (it.hasNext()) {
      Unit unit = it.next();

      if (unit instanceof IfStmt || unit instanceof GotoStmt || unit instanceof ThrowStmt) {
        complexity++;
      } else if (it.hasNext() && (unit instanceof ReturnStmt || unit instanceof ReturnVoidStmt)) {
        complexity++;
      } else if (unit instanceof LookupSwitchStmt) {
        complexity += ((LookupSwitchStmt) unit).getTargetCount();
      }

      for (ValueBox box : unit.getUseAndDefBoxes()) {
        Value value = box.getValue();
        if (value instanceof AndExpr || value instanceof OrExpr) {
          complexity++;
        }
      }
    }

    complexity += (new LoopFinder().getLoops(unitGraph)).size();

    return complexity;
  }

  private Integer calculateConditionComplexity(Value value, Integer complexity) {
    List<ValueBox> boxList = value.getUseBoxes();

    if (boxList.size() == 0) {
      if (value instanceof AndExpr || value instanceof OrExpr) {
        return 1;
      } else {
        return 0;
      }
    }

    for (ValueBox box : boxList) {
      complexity += this.calculateConditionComplexity(box.getValue(), complexity);
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
              return e1.tgt().getName().compareTo(e2.tgt().getName());
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

      boolean excluded = false;
      for (String prefix : this.excludeList) {
        if (className.startsWith(prefix)) {
          excluded = true;
          break;
        }
      }

      if (cg.edgesOutOf(edge.tgt()).hasNext() && !excluded) {
        edgeList.add(edge);
      } else {
        Set<String> classNameSet;
        if (this.edgeClassMap.containsKey(matchStr)) {
          classNameSet = new HashSet<String>(this.edgeClassMap.get(matchStr));
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

  /**
   * The method retrieves the invocation body of a statement if existed. Then it determines the
   * information of the method invoked and stores them in the result to record the callsite
   * information of the invoked method in its parent method.
   *
   * @param stmt the statement to handle
   * @param sourceFilePath the file path for the parent method
   * @return the callsite object to store in the output yaml file
   */
  private Callsite handleMethodInvocationInStatement(Stmt stmt, String sourceFilePath) {
    // Handle statements of a method
    if ((stmt.containsInvokeExpr()) && (sourceFilePath != null)) {
      InvokeExpr expr = stmt.getInvokeExpr();
      Callsite callsite = new Callsite();
      SootMethod target = expr.getMethod();
      if (!this.excludeMethodList.contains(target.getName())) {
        callsite.setSource(sourceFilePath + ":" + stmt.getJavaSourceStartLineNumber() + ",1");
        callsite.setMethodName("[" + target.getDeclaringClass() + "]." + target.getName());
        return callsite;
      }
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

  public List<String> getIncludeList() {
    return includeList;
  }

  public List<String> getExcludeList() {
    return excludeList;
  }
}
