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

import java.util.LinkedList;
import java.util.List;
import ossf.fuzz.introspector.soot.yaml.Callsite;
import ossf.fuzz.introspector.soot.yaml.FunctionConfig;
import ossf.fuzz.introspector.soot.yaml.FunctionElement;
import soot.toolkits.graph.Block;
import soot.toolkits.graph.BlockGraph;

public class CalculationUtils {
  private static List<FunctionElement> depthHandled;

  public static Integer calculateCyclomaticComplexity(BlockGraph blockGraph) {
    Integer nodes = blockGraph.size();
    Integer edges = 0;

    // Count edges of the blockGraph
    for (Block block : blockGraph.getBlocks()) {
      edges += blockGraph.getSuccsOf(block).size();
    }

    Integer complexity = edges - nodes + 2;
    if (complexity < 1) {
      complexity = 1;
    }
    return complexity;
  }

  public static void calculateAllCallDepth(FunctionConfig methodList) {
    List<FunctionElement> newMethodList = new LinkedList<FunctionElement>();
    depthHandled = new LinkedList<FunctionElement>();

    for (FunctionElement element : methodList.getFunctionElements()) {
      if (!element.getFunctionName().contains("init>")) {
        calculateCallDepth(methodList, element, null);
        for (FunctionElement handledElement : depthHandled) {
          newMethodList.add(handledElement);
        }
      } else {
        newMethodList.add(element);
      }
    }

    methodList.setFunctionElements(newMethodList);
  }

  private static Integer calculateCallDepth(
      FunctionConfig methodList, FunctionElement element, List<FunctionElement> handled) {
    if (handled == null) {
      handled = new LinkedList<FunctionElement>();
    }

    List<String> handledName = new LinkedList<String>();
    for (FunctionElement handledElement : handled) {
      handledName.add(handledElement.getFunctionName());
    }

    Integer depth = element.getFunctionDepth();
    if (!handledName.contains(element.getFunctionName())) {
      handled.add(element);
      if (depth == 0) {
        for (Callsite callsite : element.getCallsites()) {
          String callerName = callsite.getMethodName();
          FunctionElement caller = methodList.searchElement(callerName);
          if (caller != null) {
            Integer newDepth = calculateCallDepth(methodList, caller, handled) + 1;
            depth = (newDepth > depth) ? newDepth : depth;
          }
        }
      }
      element.setFunctionDepth(depth);
    }
    depthHandled = handled;

    return depth;
  }
}
