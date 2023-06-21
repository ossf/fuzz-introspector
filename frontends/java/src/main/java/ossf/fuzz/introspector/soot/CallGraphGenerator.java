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
import ossf.fuzz.introspector.soot.yaml.ClassField;
import ossf.fuzz.introspector.soot.yaml.FunctionConfig;
import ossf.fuzz.introspector.soot.yaml.FunctionElement;
import ossf.fuzz.introspector.soot.yaml.FuzzerConfig;
import ossf.fuzz.introspector.soot.yaml.JavaMethodInfo;
import soot.Body;
import soot.PackManager;
import soot.ResolutionFailedException;
import soot.Scene;
import soot.SceneTransformer;
import soot.SootClass;
import soot.SootField;
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
    if (args.length < 6 || args.length > 7) {
      System.err.println("No jarFiles, entryClass, entryMethod and target package.");
      return;
    }
    List<String> jarFiles =
        CallGraphGenerator.handleJarFilesWildcard(Arrays.asList(args[0].split(":")));
    String entryClass = args[1];
    String entryMethod = args[2];
    String targetPackagePrefix = args[3];
    String excludeMethod = args[4];
    Boolean isAutoFuzz = (args[5].equals("True")) ? true : false;
    String includePrefix = "";
    String excludePrefix = "";
    String sinkMethod = "";
    if (args.length == 7) {
      includePrefix = args[6].split("===")[0];
      excludePrefix = args[6].split("===")[1];
      sinkMethod = args[6].split("===")[2];
    }
    if (jarFiles.size() < 1) {
      System.err.println("Invalid jarFiles");
    }

    System.out.println("[Callgraph] Jar files used for analysis: " + jarFiles);

    soot.G.reset();

    // Add an custom analysis phase to Soot
    CustomSenceTransformer custom =
        new CustomSenceTransformer(
            entryClass,
            entryMethod,
            targetPackagePrefix,
            excludeMethod,
            includePrefix,
            excludePrefix,
            sinkMethod,
            isAutoFuzz);
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

    // Special options to ignore wrong staticness methods
    // For example, invoking a static class method from its
    // instance object will trigger resolve error because of
    // wrong staticness invocation
    Options.v().set_wrong_staticness(Options.wrong_staticness_ignore);

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

  public static List<String> handleJarFilesWildcard(List<String> jarFiles) {
    List<String> resultList = new LinkedList<String>();
    for (String jarFile : jarFiles) {
      if (jarFile.endsWith("*.jar")) {
        File dir = new File(jarFile.substring(0, jarFile.lastIndexOf("/")));
        if (dir.isDirectory()) {
          for (File file : dir.listFiles()) {
            String fileName = file.getAbsolutePath();
            if (fileName.endsWith(".jar")) {
              resultList.add(fileName);
            }
          }
        }
      } else {
        resultList.add(jarFile);
      }
    }
    return resultList;
  }
}

class CustomSenceTransformer extends SceneTransformer {
  private List<String> targetPackageList;
  private List<String> includeList;
  private List<String> excludeList;
  private List<String> excludeMethodList;
  private List<SootMethod> reachedSinkMethodList;
  private Map<String, Set<String>> edgeClassMap;
  private Map<String, Set<String>> sinkMethodMap;
  private String entryClassStr;
  private String entryMethodStr;
  private SootMethod entryMethod;
  private FunctionConfig methodList;
  private Boolean isAutoFuzz;

  public CustomSenceTransformer(
      String entryClassStr,
      String entryMethodStr,
      String targetPackagePrefix,
      String excludeMethodStr,
      String includePrefix,
      String excludePrefix,
      String sinkMethod) {
    this(
        entryClassStr,
        entryMethodStr,
        targetPackagePrefix,
        excludeMethodStr,
        includePrefix,
        excludePrefix,
        sinkMethod,
        false);
  }

  public CustomSenceTransformer(
      String entryClassStr,
      String entryMethodStr,
      String targetPackagePrefix,
      String excludeMethodStr,
      String includePrefix,
      String excludePrefix,
      String sinkMethod,
      Boolean isAutoFuzz) {
    this.entryClassStr = entryClassStr;
    this.entryMethodStr = entryMethodStr;
    this.isAutoFuzz = isAutoFuzz;
    this.entryMethod = null;

    targetPackageList = new LinkedList<String>();
    includeList = new LinkedList<String>();
    excludeList = new LinkedList<String>();
    excludeMethodList = new LinkedList<String>();
    reachedSinkMethodList = new LinkedList<SootMethod>();
    edgeClassMap = new HashMap<String, Set<String>>();
    sinkMethodMap = new HashMap<String, Set<String>>();
    methodList = new FunctionConfig();

    if (!targetPackagePrefix.equals("ALL")) {
      for (String targetPackage : targetPackagePrefix.split(":")) {
        if (!targetPackage.equals("")) {
          targetPackageList.add(targetPackage);
        }
      }
    }
    for (String include : includePrefix.split(":")) {
      if (!include.equals("")) {
        includeList.add(include);
      }
    }
    includeList.add(entryClassStr);
    for (String exclude : excludePrefix.split(":")) {
      if (!exclude.equals("")) {
        excludeList.add(exclude);
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
      // of the target package
      // If target package prefix has been specified and the
      // classes are not in those package, ignore it
      if (!isIgnore && !isSinkClass && !isInclude && this.hasTargetPackage()) {
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
      }

      if (!isIgnore) {
        System.out.println("[Callgraph] [USE] class: " + cname);
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
        System.out.println("[Callgraph] [SKIP] class: " + cname);
      }
      if (isAutoFuzz) {
        this.includeConstructor(c);
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
        element.setFunctionSourceFile(c.getFilePath());
        element.setFunctionLinenumber(m.getJavaSourceStartLineNumber());
        element.setReturnType(m.getReturnType().toString());
        element.setFunctionDepth(0);
        element.setArgCount(m.getParameterCount());
        for (soot.Type type : m.getParameterTypes()) {
          element.addArgType(type.toString());
        }
        if (isAutoFuzz) {
          JavaMethodInfo methodInfo = new JavaMethodInfo();
          methodInfo.setIsConcrete(m.isConcrete());
          methodInfo.setIsJavaLibraryMethod(m.isJavaLibraryMethod());
          methodInfo.setIsPublic(m.isPublic());
          methodInfo.setIsStatic(m.isStatic());
          methodInfo.setIsClassEnum(c.isEnum());
          methodInfo.setIsClassPublic(c.isPublic());
          for (SootClass exception : m.getExceptions()) {
            methodInfo.addException(exception.getFilePath());
          }
          element.setJavaMethodInfo(methodInfo);
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
              tgt.getSubSignature().split(" ")[1],
              (edge.srcStmt() == null) ? -1 : edge.srcStmt().getJavaSourceStartLineNumber());
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
          this.addMethodElement(element);
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
        element.setiCount(iCount);

        // Calculate method cyclomatic complexity from method unit graph
        UnitGraph unitGraph = new BriefUnitGraph(methodBody);
        element.setCyclomaticComplexity(calculateCyclomaticComplexity(unitGraph));

        this.addMethodElement(element);
      }
    }
    try {
      if (methodList.getFunctionElements().size() == 0) {
        throw new RuntimeException(
            "No method in analysing scope, consider relaxing the exclude constraint.");
      }

      this.includeSinkMethod();

      // Extract call tree and write to .data
      System.out.println("Generating fuzzerLogFile-" + this.entryClassStr + ".data");
      File file = new File("fuzzerLogFile-" + this.entryClassStr + ".data");
      file.createNewFile();
      FileWriter fw = new FileWriter(file);
      this.edgeClassMap = new HashMap<String, Set<String>>();
      this.extractCallTree(fw, callGraph, this.entryMethod, 0, -1);
      fw.close();

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
    System.out.println("Finish processing for fuzzer: " + this.entryClassStr);
  }

  // Include empty profile for class constructor for reference
  private void includeConstructor(SootClass sootClass) {
    List<SootMethod> mList = new LinkedList<SootMethod>(sootClass.getMethods());
    for (SootMethod method : mList) {
      if (method.getName().equals("<init>")) {
        FunctionElement element = new FunctionElement();
        String name = "[" + sootClass.getName() + "]." + method.getSubSignature().split(" ")[1];
        element.setFunctionName(name);
        element.setFunctionSourceFile(sootClass.getName());
        element.setFunctionLinenumber(method.getJavaSourceStartLineNumber());
        element.setReturnType("");
        element.setFunctionDepth(0);
        element.setArgCount(method.getParameterCount());
        for (soot.Type type : method.getParameterTypes()) {
          element.addArgType(type.toString());
        }
        element.setFunctionUses(0);
        element.setEdgeCount(0);
        element.setBBCount(0);
        element.setiCount(0);
        element.setCyclomaticComplexity(0);

        JavaMethodInfo methodInfo = new JavaMethodInfo();
        methodInfo.setIsConcrete(method.isConcrete());
        methodInfo.setIsPublic(method.isPublic());
        methodInfo.setIsClassConcrete(sootClass.isConcrete());
        methodInfo.setIsClassEnum(sootClass.isEnum());
        methodInfo.setIsClassPublic(sootClass.isPublic());
        if (sootClass.hasSuperclass()) {
          methodInfo.setSuperClass(sootClass.getSuperclass().getName());
        }
        for (SootClass exception : method.getExceptions()) {
          methodInfo.addException(exception.getFilePath());
        }
        Iterator<SootClass> interfaces = sootClass.getInterfaces().snapshotIterator();
        while (interfaces.hasNext()) {
          methodInfo.addInterface(interfaces.next().getName());
        }
        Iterator<SootField> fields = sootClass.getFields().snapshotIterator();
        while (fields.hasNext()) {
          SootField field = fields.next();
          ClassField classField = new ClassField();

          classField.setFieldName(field.getName());
          classField.setFieldType(field.getType().toString());
          classField.setIsConcrete(field.isDeclared());
          classField.setIsPublic(field.isPublic());
          classField.setIsStatic(field.isStatic());
          classField.setIsFinal(field.isFinal());

          methodInfo.addClassField(classField);
        }

        element.setJavaMethodInfo(methodInfo);

        this.addMethodElement(element);
      }
    }
  }

  // Include empty profile for touched sink methods
  private void includeSinkMethod() {
    for (SootMethod method : this.reachedSinkMethodList) {
      SootClass cl = method.getDeclaringClass();
      FunctionElement element = new FunctionElement();
      element.setFunctionName("[" + cl.getName() + "]." + method.getSubSignature().split(" ")[1]);
      element.setFunctionSourceFile(cl.getName());
      element.setFunctionLinenumber(method.getJavaSourceStartLineNumber());
      element.setReturnType(method.getReturnType().toString());
      element.setFunctionDepth(0);
      element.setArgCount(method.getParameterCount());
      for (soot.Type type : method.getParameterTypes()) {
        element.addArgType(type.toString());
      }
      element.setFunctionUses(0);
      element.setEdgeCount(0);
      element.setBBCount(0);
      element.setiCount(0);
      element.setCyclomaticComplexity(0);

      if (isAutoFuzz) {
        JavaMethodInfo methodInfo = new JavaMethodInfo();
        methodInfo.setIsConcrete(method.isConcrete());
        methodInfo.setIsJavaLibraryMethod(method.isJavaLibraryMethod());
        methodInfo.setIsPublic(method.isPublic());
        methodInfo.setIsStatic(method.isStatic());
        methodInfo.setIsClassEnum(method.getDeclaringClass().isEnum());
        methodInfo.setIsClassPublic(method.getDeclaringClass().isPublic());
        for (SootClass exception : method.getExceptions()) {
          methodInfo.addException(exception.getFilePath());
        }
        element.setJavaMethodInfo(methodInfo);
      }

      this.addMethodElement(element);
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

  // Add method element to the method list, ignoring method already added to the list
  private void addMethodElement(FunctionElement element) {
    if (this.searchElement(element.getFunctionName()) == null) {
      this.methodList.addFunctionElement(element);
    }
  }

  // Shorthand for extractCallTree from top
  private void extractCallTree(
      FileWriter fw, CallGraph cg, SootMethod method, Integer depth, Integer line)
      throws IOException {
    fw.write("Call tree\n");
    this.extractCallTree(fw, cg, method, depth, line, new LinkedList<SootMethod>(), null);
  }

  // Recursively extract calltree from stored method relationship, ignoring loops
  // and write to the output data file
  private Integer extractCallTree(
      FileWriter fw,
      CallGraph cg,
      SootMethod method,
      Integer depth,
      Integer line,
      List<SootMethod> handled,
      String callerClass)
      throws IOException {
    StringBuilder callTree = new StringBuilder();

    if (this.excludeMethodList.contains(method.getName())) {
      return 0;
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
    String calltreeLine =
        StringUtils.leftPad("", depth * 2)
            + methodName
            + " "
            + className
            + " linenumber="
            + line
            + "\n";

    boolean excluded = false;
    boolean sink = false;
    checkExclusionLoop:
    for (String cl : className.split(":")) {
      for (String prefix : this.excludeList) {
        if (cl.startsWith(prefix.replace("*", ""))) {
          if (sinkMethodMap.getOrDefault(cl, Collections.emptySet()).contains(method.getName())) {
            sink = true;
          }
          excluded = true;
          break checkExclusionLoop;
        }
      }
    }

    if (excluded) {
      if (sink) {
        fw.write(calltreeLine);
      }
      return 0;
    } else {
      fw.write(calltreeLine);
    }

    FunctionElement element = this.searchElement("[" + className + "]." + methodName);

    if (!handled.contains(method)) {
      handled.add(method);
      Iterator<Edge> outEdges = this.mergePolymorphism(cg, cg.edgesOutOf(method));
      while (outEdges.hasNext()) {
        Edge edge = outEdges.next();
        SootMethod tgt = edge.tgt();

        if (tgt.equals(edge.src())) {
          continue;
        }

        Integer resultDepth =
            extractCallTree(
                fw,
                cg,
                tgt,
                depth + 1,
                (edge.srcStmt() == null) ? -1 : edge.srcStmt().getJavaSourceStartLineNumber(),
                handled,
                edge.src().getDeclaringClass().getName());
        Integer newDepth = resultDepth + 1;
        if ((element != null) && (newDepth > element.getFunctionDepth())) {
          element.setFunctionDepth(newDepth);
        }
      }
    }

    return (element == null) ? 0 : element.getFunctionDepth();
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
            Integer e1LineNo =
                (e1.srcStmt() == null) ? -1 : e1.srcStmt().getJavaSourceStartLineNumber();
            Integer e2LineNo =
                (e2.srcStmt() == null) ? -1 : e2.srcStmt().getJavaSourceStartLineNumber();
            int line = e1LineNo - e2LineNo;
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
    List<Edge> processingEdgeList = new LinkedList<Edge>();
    Edge previous = null;

    it = this.sortEdgeByLineNumber(it);

    while (it.hasNext()) {
      Edge edge = it.next();
      String className = edge.tgt().getDeclaringClass().getName();
      String matchStr =
          edge.src().getDeclaringClass().getName()
              + ":"
              + edge.tgt().getName()
              + ":"
              + ((edge.srcStmt() == null) ? -1 : edge.srcStmt().getJavaSourceStartLineNumber());

      boolean excluded = false;
      for (String prefix : this.excludeList) {
        if (className.startsWith(prefix.replace("*", ""))) {
          if (!this.getIncludeList().contains(className)) {
            excluded = true;
            break;
          }
        }
      }

      if (!excluded) {
        if (cg.edgesOutOf(edge.tgt()).hasNext()
            || edge.tgt().getName().equals("<init>")
            || edge.tgt().getName().equals("<cinit>")) {
          // Does not merge methods with deeper method calls
          // Does not merge edge for constructor calls
          edgeList.add(edge);
        } else {
          // Merge previously processed methods when this edge
          // is differ from the last one cause edges are sorted
          if (previous != null) {
            String edgeName = edge.tgt().getName();
            String previousEdgeName = previous.tgt().getName();
            Integer edgeLineNo =
                (edge.srcStmt() == null) ? -1 : edge.srcStmt().getJavaSourceStartLineNumber();
            Integer previousEdgeLineNo =
                (previous.srcStmt() == null)
                    ? -1
                    : previous.srcStmt().getJavaSourceStartLineNumber();
            if (!(edgeName.equals(previousEdgeName)) || !(edgeLineNo == previousEdgeLineNo)) {
              if (processingEdgeList.size() > 0) {
                Set<String> classNameSet = new HashSet<String>();
                for (Edge mergeEdge : processingEdgeList) {
                  classNameSet.add(mergeEdge.tgt().getDeclaringClass().getName());
                }
                if (classNameSet.size() > 1) {
                  this.edgeClassMap.put(matchStr, classNameSet);
                }
                edgeList.add(processingEdgeList.get(0));
                processingEdgeList = new LinkedList<Edge>();
              }
            }
          }
          processingEdgeList.add(edge);
        }
      }
      previous = edge;
    }

    // Merge the final group of processed methods
    if (processingEdgeList.size() > 0) {
      Edge edgeToAdd = processingEdgeList.get(0);
      edgeList.add(edgeToAdd);
      Set<String> classNameSet = new HashSet<String>();
      for (Edge mergeEdge : processingEdgeList) {
        classNameSet.add(mergeEdge.tgt().getDeclaringClass().getName());
      }
      if (classNameSet.size() > 1) {
        String matchStr =
            edgeToAdd.src().getDeclaringClass().getName()
                + ":"
                + edgeToAdd.tgt().getName()
                + ":"
                + ((edgeToAdd.srcStmt() == null)
                    ? -1
                    : edgeToAdd.srcStmt().getJavaSourceStartLineNumber());
        this.edgeClassMap.put(matchStr, classNameSet);
      }
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
}
