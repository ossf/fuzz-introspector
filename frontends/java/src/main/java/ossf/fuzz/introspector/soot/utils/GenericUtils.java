// Copyright 2024 Fuzz Introspector Authors
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

import com.github.javaparser.JavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.Parameter;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import ossf.fuzz.introspector.soot.yaml.FunctionElement;
import soot.SootMethod;

public class GenericUtils {
  private static Map<String, Path> sourcePaths = new HashMap<String, Path>();

  /**
   * This method adds mapping to the sourcePaths hash map to allow the
   * discovering the generic of certain methods return type nad argument
   * types through source code analysis.
   * @param sourceName the name of the public class of the source file
   * @param sourcePath the absolute path of the source file
   */
  public static void addSourcePath(String sourceName, Path sourcePath) {
    sourcePaths.put(sourceName, sourcePath);
  }

  /**
   * This method analyse the return type and the argument types of a method.
   * If source code of the target method is found. It parses the source code
   * and retrieves the return type and the argument types and determine if
   * generic has been used. If generic has been used, the generic types is
   * then added to additional fields in the FunctionElement instance to
   * indicate its generic types as additional information.
   *
   * @param m the target SootMethod object to be processed
   * @param element the target FunctionElement object to be processed
   */
  public static void updateGenericTypes(SootMethod m, FunctionElement element) {
    String className = m.getDeclaringClass().getName();
    className = className.substring(className.lastIndexOf(".") + 1);
    if (sourcePaths.containsKey(className)) {
      try {
        // Try read and parse the source file related to the class of the target method.
        InputStream is = new FileInputStream(sourcePaths.get(className).toFile());
        Optional<CompilationUnit> optional = new JavaParser().parse(is).getResult();
        if (optional.isPresent()) {
          for(MethodDeclaration md : optional.get().findAll(MethodDeclaration.class)) {
            if (md.getName().asString().equals(m.getName())) {
              if (handleArgumentGeneric(md, element)) {
                // There could be overloading method with the same name in the same class
                // handleArgumentGeneric will return true if the the MethodDeclaration
                // points to the correct method and handles it successfully.
                handleReturnTypeGeneric(md, element);
              }
            }
          }
        }
      } catch (IOException e) {
        // Assume the source file is not found nor parsable.
        return;
      }
    }
  }

  private static void handleReturnTypeGeneric(MethodDeclaration md, FunctionElement element) {
    String returnType = element.getReturnType();
    String realReturnType = md.getType().asString();

    if (!returnType.equals(realReturnType)) {
      if (containsGeneric(realReturnType)) {
        if (returnType.contains(".")) {
          returnType = returnType.substring(0, returnType.lastIndexOf("."));
          element.setReturnType(returnType + "." + realReturnType);
        } else {
          element.setReturnType(realReturnType);
        }
      }
    }
  }

  private static boolean handleArgumentGeneric(MethodDeclaration md, FunctionElement element) {
    List<String> argTypes = element.getArgTypes();
    List<Parameter> mdArgTypes = md.getParameters();

    if (argTypes.size() > 0 && argTypes.size() == mdArgTypes.size()) {
      List<String> newArgTypes = new ArrayList<String>();
      Boolean isGeneric = false;
      for (Integer i = 0; i < argTypes.size(); i++) {
        String mdArgType = mdArgTypes.get(i).getType().asString();
        String argType = argTypes.get(i);

        // Check equality of the two argument types to ensure
        // it is the correct MethodDeclaration of the target method
        if (!isSameArgType(argType, mdArgType)) {
          return false;
        }

        // Add the arguments with or without generic to the function elements
        if (containsGeneric(mdArgType)) {
          if (argType.contains(".")) {
            argType = argType.substring(0, argType.lastIndexOf("."));
            newArgTypes.add(argType + "." + mdArgType);
          } else {
            newArgTypes.add(mdArgType);
          }
          isGeneric = true;
        } else {
          newArgTypes.add(argTypes.get(i));
        }
      }

      // Save method name with generic
      if (isGeneric) {
        String functionName = element.getFunctionName().split("\\(")[0];
        String argString = String.join(",", newArgTypes);
        element.setFunctionName(String.format("%s(%s)", functionName, argString));
        element.setArgTypes(newArgTypes);
      }

      return true;
    }
    return false;
  }

  private static boolean containsGeneric(String type) {
    if (type.contains("<") && type.contains(">")) {
      return true;
    } else {
      return false;
    }
  }

  private static boolean isSameArgType(String argType, String mdArgType) {
    String simpleArgType = null;
    String simpleMdArgType = null;

    // Simplify argType
    if (argType.contains(".")) {
      simpleArgType = argType.substring(argType.lastIndexOf(".") + 1);
    } else {
      simpleArgType = argType;
    }

    // Simplify mdArgType
    if (containsGeneric(mdArgType)) {
      simpleMdArgType = mdArgType.split("<")[0];
    } else {
      simpleMdArgType = mdArgType;
    }

    return simpleArgType.equals(simpleMdArgType);
  }
}
