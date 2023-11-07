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

import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import ossf.fuzz.introspector.soot.yaml.FunctionElement;
import soot.SootMethod;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;

public class EdgeUtils {
  /**
   * The method retrieves a list of incoming edges from the provided SootMethod and calculate the
   * total number of incoming edges and store it in the provided FunctionElement object
   *
   * @param callGraph the CallGraph object for this target project
   * @param m the target SootMethod object to be processed
   * @param element the target FunctionElement object to be processed
   */
  public static void updateIncomingEdges(
      CallGraph callGraph, SootMethod m, FunctionElement element) {
    Integer edges = 0;

    Iterator<Edge> inEdges = callGraph.edgesInto(m);
    while (inEdges.hasNext()) {
      edges++;
      inEdges.next();
    }

    element.setFunctionUses(edges);
  }

  /**
   * The method retrieves a list of outgoing edges from the provided SootMethod and calculate the
   * total number of outgoing edges. The process will include or exclude some classes and methods
   * according to the three lists provided. Lastly, the edge count and method targets pointed out by
   * the included edges are stored in the provided FunctionElement object.
   *
   * @param callGraph the CallGraph object for this target project
   * @param m the target SootMethod object to be processed
   * @param element the target FunctionElement object to be processed
   * @param includeList a list to store all whitelist class names for this run
   * @param excludeList a list to store all blacklist class names for this run
   * @param excludeMethodList a list to store all backlist method names for this run
   * @param edgeClassMap a map to store class names with polymorphism methods that are merged
   * @param functionLineMap a map object to store the starting line number of known methods
   */
  public static void updateOutgoingEdges(
      CallGraph callGraph,
      SootMethod m,
      FunctionElement element,
      List<String> includeList,
      List<String> excludeList,
      List<String> excludeMethodList,
      Map<String, Set<String>> edgeClassMap,
      Map<String, Integer> functionLineMap) {
    Integer edges = 0;
    Iterator<Edge> outEdges =
        MergeUtils.mergePolymorphism(
            callGraph, callGraph.edgesOutOf(m), excludeList, includeList, edgeClassMap);

    for (; outEdges.hasNext(); edges++) {
      Edge edge = outEdges.next();
      SootMethod tgt = edge.tgt();

      // Skip excluded method
      if (excludeMethodList.contains(tgt.getName())) {
        edges--;
        continue;
      }

      // Retrieve class name set
      String callerClass = edge.src().getDeclaringClass().getName();
      String className = "";
      Set<String> classNameSet =
          new HashSet<String>(
              edgeClassMap.getOrDefault(
                  callerClass
                      + ":"
                      + tgt.getName()
                      + ":"
                      + ((edge.srcStmt() == null)
                          ? -1
                          : edge.srcStmt().getJavaSourceStartLineNumber()),
                  Collections.emptySet()));
      className = MergeUtils.mergeClassName(classNameSet);

      // Check if class name has been merged
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

      // Store details of reached methods
      element.addFunctionsReached("[" + className + "]." + tgt.getSubSignature().split(" ")[1]);
      functionLineMap.put(
          tgt.getSubSignature().split(" ")[1],
          (edge.srcStmt() == null) ? -1 : edge.srcStmt().getJavaSourceStartLineNumber());
    }

    element.setEdgeCount(edges);
  }
}
