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
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import ossf.fuzz.introspector.soot.yaml.BranchProfile;
import ossf.fuzz.introspector.soot.yaml.BranchSide;
import ossf.fuzz.introspector.soot.yaml.Callsite;
import soot.ResolutionFailedException;
import soot.SootClass;
import soot.SootMethod;
import soot.Unit;
import soot.jimple.IfStmt;
import soot.jimple.InvokeExpr;
import soot.jimple.Stmt;
import soot.toolkits.graph.Block;

public class BlockGraphInfoUtils {
  /**
   * The method retrieves the invocation body of a statement if exists. Then it determines the
   * information on the method invoked and stores them in the result to record the call site
   * information of the invoked method in its parent method.
   *
   * @param stmt the statement to handle
   * @param sourceFilePath the file path for the parent method
   * @param isAutoFuzz a boolean value to indicate if this run is initiated by AutoFuzz
   * @param sinkMethodMap a map to store a set of sink methods names grouped by their containing
   *     classes
   * @param reachedSinkMethodList a list of sink methods which are reachable by the given entry
   *     method
   * @param excludeMethodList a list to store all excluded method names for this run
   * @return the callsite object to store in the output yaml file, return null if Soot fails to
   *     resolve the invocation
   */
  public static Callsite handleMethodInvocationInStatement(
      Stmt stmt,
      String sourceFilePath,
      Boolean isAutoFuzz,
      Map<String, Set<String>> sinkMethodMap,
      List<SootMethod> reachedSinkMethodList,
      List<String> excludeMethodList) {
    // Handle statements of a method
    try {
      if ((stmt.containsInvokeExpr()) && (sourceFilePath != null)) {
        InvokeExpr expr = stmt.getInvokeExpr();
        Callsite callsite = new Callsite();
        SootMethod target = expr.getMethod();
        SootClass tClass = target.getDeclaringClass();
        Set<String> sink = sinkMethodMap.getOrDefault(tClass.getName(), Collections.emptySet());
        if (sink.contains(target.getName())) {
          reachedSinkMethodList.add(target);
        }
        if (!excludeMethodList.contains(target.getName())) {
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

  /**
   * The method retrieves a BranchProfile object for the given if statement. The information
   * includes the information of the true or false blocks of code pointed by the provided if
   * statement.
   *
   * @param blocks a list of all code blocks
   * @param unit the Unit object that contains the if statement block
   * @param cname the name of the class where the target code block belongs
   * @param functionLineMap a map object to store the starting line number of known methods
   * @return the BranchProfile object with all the source information for the if statement
   */
  public static BranchProfile handleIfStatement(
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

  private static BranchSide processBranch(
      Map<String, Integer> blockLine, String cname, Map<String, Integer> functionLineMap) {
    BranchSide branchSide = new BranchSide();

    Integer start = blockLine.get("start");
    Integer end = blockLine.get("end");
    branchSide.setBranchSideStr(cname);
    branchSide.setBranchSideFuncs(getFunctionCallInTargetLine(functionLineMap, start, end));

    return branchSide;
  }

  private static Map<String, Integer> getBlockStartEndLineWithLineNumber(
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

  private static List<String> getFunctionCallInTargetLine(
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
}
