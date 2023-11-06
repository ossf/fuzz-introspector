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

package ossf.fuzz.introspector.soot.utils;

import java.io.FileWriter;
import java.io.IOException;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.commons.lang3.StringUtils;
import ossf.fuzz.introspector.soot.yaml.FunctionConfig;
import ossf.fuzz.introspector.soot.yaml.FunctionElement;
import soot.SootClass;
import soot.SootMethod;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;

public class CalltreeUtils {
  private static List<String> includeList;
  private static List<String> excludeList;
  private static List<String> excludeMethodList;
  private static Map<String, Set<String>> edgeClassMap;
  private static Map<String, Set<String>> sinkMethodMap;

  // Save base data for calltree generation
  public static void setBaseData(
      List<String> includeList,
      List<String> excludeList,
      List<String> excludeMethodList,
      Map<String, Set<String>> edgeClassMap,
      Map<String, Set<String>> sinkMethodMap) {
    CalltreeUtils.includeList = includeList;
    CalltreeUtils.excludeList = excludeList;
    CalltreeUtils.excludeMethodList = excludeMethodList;
    CalltreeUtils.edgeClassMap = edgeClassMap;
    CalltreeUtils.sinkMethodMap = sinkMethodMap;
  }

  // Utils to get a list of FunctionElement for all constructors of sootClass
  public static void addConstructors(FunctionConfig methodList, SootClass sootClass) {
    List<FunctionElement> eList = new LinkedList<FunctionElement>();

    List<SootMethod> mList = new LinkedList<SootMethod>(sootClass.getMethods());
    for (SootMethod method : mList) {
      if (method.getName().equals("<init>")) {
        String name = "[" + sootClass.getName() + "]." + method.getSubSignature().split(" ")[1];

        FunctionElement element = new FunctionElement();
        element.setFunctionName(name);
        element.setBaseInformation(method);
        element.setJavaMethodInfo(method);

        eList.add(element);
      }
    }

    methodList.addFunctionElements(eList);
  }

  // Utils to get a list of FunctionElement of all reached sink methods
  public static void addSinkMethods(
      FunctionConfig methodList, List<SootMethod> reachedSinkMethodList, Boolean isAutoFuzz) {
    List<FunctionElement> eList = new LinkedList<FunctionElement>();

    for (SootMethod method : reachedSinkMethodList) {
      SootClass cl = method.getDeclaringClass();

      FunctionElement element = new FunctionElement();
      element.setFunctionName("[" + cl.getName() + "]." + method.getSubSignature().split(" ")[1]);
      element.setBaseInformation(method);
      if (isAutoFuzz) {
        element.setJavaMethodInfo(method);
      }

      eList.add(element);
    }

    methodList.addFunctionElements(eList);
  }

  // Shorthand for extractCallTree from top
  public static void extractCallTree(
      FileWriter fw, CallGraph cg, SootMethod method, Integer depth, Integer line)
      throws IOException {
    fw.write("Call tree\n");
    extractCallTree(fw, cg, method, depth, line, new LinkedList<SootMethod>(), null);
  }

  // Recursively extract calltree from stored method relationship, ignoring loops
  // and write to the output data file
  private static void extractCallTree(
      FileWriter fw,
      CallGraph cg,
      SootMethod method,
      Integer depth,
      Integer line,
      List<SootMethod> handled,
      String callerClass)
      throws IOException {
    StringBuilder callTree = new StringBuilder();

    if (excludeMethodList.contains(method.getName())) {
      return;
    }

    String className = "";
    if (callerClass != null) {
      Set<String> classNameSet =
          new HashSet<String>(
              edgeClassMap.getOrDefault(
                  callerClass + ":" + method.getName() + ":" + line, Collections.emptySet()));
      className = MergeUtils.mergeClassName(classNameSet);
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
      for (String prefix : excludeList) {
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
      return;
    } else {
      fw.write(calltreeLine);
    }

    if (!handled.contains(method)) {
      handled.add(method);
      Iterator<Edge> outEdges =
          MergeUtils.mergePolymorphism(
              cg, cg.edgesOutOf(method), includeList, excludeList, edgeClassMap);
      while (outEdges.hasNext()) {
        Edge edge = outEdges.next();
        SootMethod tgt = edge.tgt();

        if (tgt.equals(edge.src())) {
          continue;
        }

        extractCallTree(
            fw,
            cg,
            tgt,
            depth + 1,
            (edge.srcStmt() == null) ? -1 : edge.srcStmt().getJavaSourceStartLineNumber(),
            handled,
            edge.src().getDeclaringClass().getName());
      }
    }
  }
}
