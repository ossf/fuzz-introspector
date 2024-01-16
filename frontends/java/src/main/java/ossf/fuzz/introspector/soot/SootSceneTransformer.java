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
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import ossf.fuzz.introspector.soot.utils.BlockGraphInfoUtils;
import ossf.fuzz.introspector.soot.utils.CalculationUtils;
import ossf.fuzz.introspector.soot.utils.CalltreeUtils;
import ossf.fuzz.introspector.soot.utils.EdgeUtils;
import ossf.fuzz.introspector.soot.utils.SinkDiscoveryUtils;
import ossf.fuzz.introspector.soot.yaml.Callsite;
import ossf.fuzz.introspector.soot.yaml.FunctionConfig;
import ossf.fuzz.introspector.soot.yaml.FunctionElement;
import ossf.fuzz.introspector.soot.yaml.FuzzerConfig;
import soot.Body;
import soot.Scene;
import soot.SceneTransformer;
import soot.SootClass;
import soot.SootMethod;
import soot.Unit;
import soot.jimple.IfStmt;
import soot.jimple.Stmt;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.toolkits.graph.Block;
import soot.toolkits.graph.BlockGraph;
import soot.toolkits.graph.BriefBlockGraph;

public class SootSceneTransformer extends SceneTransformer {
  private List<String> targetPackageList;
  private List<String> includeList;
  private List<String> excludeList;
  private List<String> excludeMethodList;
  private List<String> projectClassList;
  private List<SootMethod> fullSinkMethodList;
  private List<FunctionElement> depthHandled;
  private Map<String, Set<String>> edgeClassMap;
  private Map<String, Set<String>> sinkMethodMap;
  private Map<SootClass, List<SootMethod>> projectClassMethodMap;
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
    fullSinkMethodList = new LinkedList<SootMethod>();
    edgeClassMap = new HashMap<String, Set<String>>();
    sinkMethodMap = new HashMap<String, Set<String>>();
    projectClassMethodMap = new HashMap<SootClass, List<SootMethod>>();
    methodList = new FunctionConfig();
    analyseFinished = false;

    // Process the target package prefix string
    if (!targetPackagePrefix.equals("ALL")) {
      for (String targetPackage : targetPackagePrefix.split(":")) {
        if (!targetPackage.equals("")) {
          targetPackageList.add(targetPackage);
        }
      }
    }

    // Retrieve a list of class for the target project source directory
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

    // Process the whitelist of class prefix
    for (String include : includePrefix.split(":")) {
      if (!include.equals("")) {
        includeList.add(include);
      }
    }
    includeList.add(entryClassStr);

    // Process the blacklist of class prefix
    if (projectClassList.size() == 0) {
      for (String exclude : excludePrefix.split(":")) {
        if (!exclude.equals("")) {
          excludeList.add(exclude);
        }
      }
    }

    // Process the blacklist of method
    for (String exclude : excludeMethodStr.split(":")) {
      excludeMethodList.add(exclude);
    }

    // Gather a list of possible sink methods in Java
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
    CallGraph callGraph = Scene.v().getCallGraph();

    System.out.println("[Callgraph] Internal transform init");
    System.out.println("[Callgraph] Determining classes to use for analysis.");

    Map<SootClass, List<SootMethod>> classMethodMap =
        this.generateClassMethodMap(Scene.v().getClasses().snapshotIterator());

    System.out.println("[Callgraph] Finished going through classes");

    this.processMethods(classMethodMap, callGraph);

    if (methodList.getFunctionElements().size() == 0) {
      throw new RuntimeException(
          "No method in analysing scope, consider relaxing the exclude constraint.");
    }

    try {
      CalculationUtils.calculateAllCallDepth(this.methodList);

      if (!isAutoFuzz) {
        fullSinkMethodList = SinkDiscoveryUtils.discoverAllSinks(sinkMethodMap, projectClassMethodMap, callGraph);
        CalltreeUtils.addSinkMethods(this.methodList, this.fullSinkMethodList, this.isAutoFuzz);
      }

      // Extract call tree and write to .data
      System.out.println("[Callgraph] Generating fuzzerLogFile-" + this.entryClassStr + ".data");
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
      System.out.println(
          "[Callgraph] Generating fuzzerLogFile-" + this.entryClassStr + ".data.yaml");
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

  private Map<SootClass, List<SootMethod>> generateClassMethodMap(
      Iterator<SootClass> classIterator) {
    Map<SootClass, List<SootMethod>> classMethodMap = new HashMap<SootClass, List<SootMethod>>();

    while (classIterator.hasNext()) {
      boolean isInclude = false;
      boolean isIgnore = false;
      boolean isSinkClass = false;
      boolean isAutoFuzzIgnore = false;
      SootClass c = classIterator.next();
      String cname = c.getName();

      // Add data for the full project class method map
      this.projectClassMethodMap.put(c, c.getMethods());

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
      }
      if (isAutoFuzz && !isAutoFuzzIgnore) {
        CalltreeUtils.addConstructors(this.methodList, c);
      }
    }

    return classMethodMap;
  }

  private void processMethods(
      Map<SootClass, List<SootMethod>> classMethodMap, CallGraph callGraph) {
    for (SootClass c : classMethodMap.keySet()) {
      // Skip sink method classes
      if (this.sinkMethodMap.containsKey(c.getName())) {
        continue;
      }

      System.out.println("Inspecting class: " + c.getName());

      // Loop through each methods in the class
      List<SootMethod> mList = new LinkedList<SootMethod>();
      mList.addAll(classMethodMap.get(c));
      for (SootMethod m : mList) {
        if (this.excludeMethodList.contains(m.getName())) {
          continue;
        }

        // Discover method related information
        FunctionElement element = new FunctionElement();
        Map<String, Integer> functionLineMap = new HashMap<String, Integer>();

        if (m.getName().equals(this.entryMethodStr) && c.getName().equals(this.entryClassStr)) {
          this.entryMethod = m;
        }

        element.setFunctionName("[" + c.getFilePath() + "]." + m.getSubSignature().split(" ")[1]);
        element.setBaseInformation(m);
        element.setJavaMethodInfo(m, isAutoFuzz);

        // Retrieve and update incoming and outgoing edges of the target method
        EdgeUtils.updateIncomingEdges(callGraph, m, element);
        EdgeUtils.updateOutgoingEdges(
            callGraph,
            m,
            element,
            this.includeList,
            this.excludeList,
            this.excludeMethodList,
            this.edgeClassMap,
            functionLineMap);

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
                  BlockGraphInfoUtils.handleMethodInvocationInStatement(
                      (Stmt) unit,
                      c.getFilePath(),
                      this.sinkMethodMap,
                      this.excludeMethodList);
              if (callsite != null) {
                element.addCallsite(callsite);
              }
              if (unit instanceof IfStmt) {
                element.addBranchProfile(
                    BlockGraphInfoUtils.handleIfStatement(
                        blockGraph.getBlocks(), unit, c.getName(), functionLineMap));
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
