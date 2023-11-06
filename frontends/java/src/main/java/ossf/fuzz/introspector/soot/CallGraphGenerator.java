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

import java.io.File;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import soot.PackManager;
import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import soot.Transform;
import soot.options.Options;
import soot.tagkit.AnnotationTag;
import soot.tagkit.VisibilityAnnotationTag;

public class CallGraphGenerator {
  public static void main(String[] args) {
    System.out.println("[Callgraph] Running callgraph plugin");

    // Handle arguments
    if (args.length < 7 || args.length > 8) {
      System.err.println("No jarFiles, entryClass, entryMethod and target package.");
      return;
    }
    List<String> jarFiles =
        CallGraphGenerator.handleJarFilesWildcard(Arrays.asList(args[0].split(":")));
    String entryClass = args[1];
    String entryMethod = args[2];
    String targetPackagePrefix = args[3];
    String excludeMethod = args[4];
    String sourceDirectory = args[5];
    Boolean isAutoFuzz = (args[6].equals("True")) ? true : false;
    String includePrefix = "";
    String excludePrefix = "";
    String sinkMethod = "";
    if (args.length == 8) {
      includePrefix = args[7].split("===")[0];
      excludePrefix = args[7].split("===")[1];
      sinkMethod = args[7].split("===")[2];
    }
    if (jarFiles.size() < 1) {
      System.err.println("Invalid jarFiles");
    }

    System.out.println("[Callgraph] Jar files used for analysis: " + jarFiles);

    soot.G.reset();

    // Add an custom analysis phase to Soot
    SootSceneTransformer transformer =
        new SootSceneTransformer(
            entryClass,
            entryMethod,
            targetPackagePrefix,
            excludeMethod,
            includePrefix,
            excludePrefix,
            sinkMethod,
            sourceDirectory,
            isAutoFuzz);

    // Set basic settings for the call graph generation
    Options.v().set_process_dir(jarFiles);
    Options.v().set_prepend_classpath(true);
    Options.v().set_src_prec(Options.src_prec_java);
    Options.v().set_include(transformer.getIncludeList());
    Options.v().set_exclude(transformer.getExcludeList());
    Options.v().set_no_bodies_for_excluded(true);
    Options.v().set_allow_phantom_refs(true);
    Options.v().set_whole_program(true);
    Options.v().set_keep_line_number(true);
    Options.v().set_no_writeout_body_releasing(true);
    Options.v().set_ignore_classpath_errors(true);
    Options.v().set_ignore_resolution_errors(true);

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
    SootMethod entryPoint = null;
    try {
      entryPoint = c.getMethodByName(entryMethod);
    } catch (RuntimeException e) {
      // Default entry method not found. Try retrieve entry method by annotation.
      outer:
      for (SootMethod method : c.getMethods()) {
        if (method.hasTag("VisibilityAnnotationTag")) {
          VisibilityAnnotationTag tag =
              (VisibilityAnnotationTag) method.getTag("VisibilityAnnotationTag");
          for (AnnotationTag annotation : tag.getAnnotations()) {
            if (annotation.getType().equals("Lcom/code_intelligence/jazzer/junit/FuzzTest;")) {
              entryPoint = method;
              break outer;
            }
          }
        }
      }
    }

    if (entryPoint == null) {
      System.out.println(
          "Cannot find method: "
              + entryMethod
              + " or methods with @FuzzTest annotation from class: "
              + entryClass
              + ".");
      return;
    }
    transformer.setEntryMethodStr(entryPoint.getName());

    List<SootMethod> entryPoints = new LinkedList<SootMethod>();
    entryPoints.add(entryPoint);
    Scene.v().setEntryPoints(entryPoints);

    // Load all related classes
    Scene.v().loadNecessaryClasses();
    Scene.v().loadDynamicClasses();

    try {
      // Start the generation
      PackManager.v().getPack("wjtp").add(new Transform("wjtp.custom", transformer));
      PackManager.v().runPacks();
    } catch (RuntimeException e) {
      if (!transformer.isAnalyseFinished()) {
        // Only flow the runtime exception when the analyse is not finished.
        // Runtime exception may happens in stages after the analyse is completed.
        throw e;
      }
    }
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
