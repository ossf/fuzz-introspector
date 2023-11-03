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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
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
import java.util.stream.Collectors;
import java.util.stream.Stream;
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
import soot.jimple.IfStmt;
import soot.jimple.InvokeExpr;
import soot.jimple.OrExpr;
import soot.jimple.Stmt;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import soot.options.Options;
import soot.tagkit.AnnotationTag;
import soot.tagkit.VisibilityAnnotationTag;
import soot.toolkits.graph.Block;
import soot.toolkits.graph.BlockGraph;
import soot.toolkits.graph.BriefBlockGraph;

public class CalltreeUtils {
  // Utils to get a list of FunctionElement for all constructors of sootClass
  public static List<FunctionElement> getConstructorList(SootClass sootClass) {
    List<FunctionElement> eList = new LinkedList<FunctionElement>();

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

        eList.add(element);
      }
    }

    return eList;
  }

  // Utils to get a list of FunctionElement of all reached sink methods
  public static List<FunctionElement> getSinkMethodList(List<SootMethod> reachedSinkMethodList, Boolean isAutoFuzz) {
    List<FunctionElement> eList = new LinkedList<FunctionElement>();

    for (SootMethod method : reachedSinkMethodList) {
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

      eList.add(element);
    }

    return eList;
  }
}
