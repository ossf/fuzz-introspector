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
import java.util.Comparator;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;

public class MergeUtils {
  public static Iterator<Edge> mergePolymorphism(
      CallGraph cg,
      Iterator<Edge> it,
      List<String> excludeList,
      List<String> includeList,
      Map<String, Set<String>> edgeClassMap) {
    List<Edge> edgeList = new LinkedList<Edge>();
    List<Edge> processingEdgeList = new LinkedList<Edge>();
    Edge previous = null;

    it = sortEdgeByLineNumber(it);

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
      for (String prefix : excludeList) {
        if (className.startsWith(prefix.replace("*", ""))) {
          if (!includeList.contains(className)) {
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
                  edgeClassMap.put(matchStr, classNameSet);
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
        edgeClassMap.put(matchStr, classNameSet);
      }
    }

    return sortEdgeByLineNumber(edgeList.iterator());
  }

  public static String mergeClassName(Set<String> classNameSet) {
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

  private static Iterator<Edge> sortEdgeByLineNumber(Iterator<Edge> it) {
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
}
