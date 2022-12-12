# Copyright 2022 Fuzz Introspector Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import sys
import subprocess
import shutil

FI_JVM_BASE="/fuzz-introspector/frontends/java"
PLUGIN_PATH="target/ossf.fuzz.introspector.soot-1.0.jar"
CGRAPH_STR="ossf.fuzz.introspector.soot.CallGraphGenerator"

target_mvn = "mvn"


def is_jvm_frontend_built():
  if not os.path.isfile(PLUGIN_PATH):
    return False
  return True


def build_jvm_frontend():
  if not is_jvm_frontend_built():
    subprocess.check_call(f"{target_mvn} clean package -Dmaven.test.skip", shell=True)

  if not is_jvm_frontend_built():
    return False
  return True


def find_fuzz_targets(path):
  print("Finding fuzz targets in %s" % path)
  jar_files = set()
  targets = list()
  for classfile in os.listdir(path):
    csp = classfile#os.path.join(path, classfile)
    print("Checking target %s" % classfile)
    if classfile.endswith(".class"):
      # We must have:
      # - An executable (wrapper script)
      # - An .class path (fuzzer class)
      # - A .jar file
      wrapper_script = classfile.replace(".class", "")
      jar_file = classfile.replace(".class", ".jar")
          
      # Check if wrapper script exsts and whether it has the right tag
      #wsp = os.path.join(path, wrapper_script)
      wsp=wrapper_script
      if not os.path.isfile(wsp):
        print("B1")
        continue

      with open(wsp) as wrapper_script_fd:
        if 'LLVMFuzzerTestOneInput' not in wrapper_script_fd.read():
          print("B2")
          continue

      # Avoid if the corresponding .jar file is not there.
      #jfp = os.path.join(path, jar_file)
      jfp = jar_file
      if not os.path.exists(jfp):
        subprocess.check_call("jar cvf %s %s" % (jfp, classfile), shell=True)
        print("B3")
        #continue
        #jfp=""

      targets.append((csp, wsp, jfp))
      if jfp != "":
        jar_files.add(jar_file)

  for jarfile in os.listdir(path):
    if not jarfile.endswith(".jar"):
      continue
    if "jazzer" in jarfile:
      continue

    jar_files.add(jarfile)

  jar_files_new = set()
  for jf in jar_files:
    if "/out/" not in jf:
      jf = "/out/" + jf
    jar_files_new.add(jf)

  jar_files = jar_files_new
  return targets, jar_files


def run_introspector_frontend(target_class, jar_set):
  print("Running introspector frontend on %s :: %s" % (target_class, jar_set))
  jarfile_str = ":".join(jar_set)
  cmd = [
      "java",
      "-Xmx6144M",
      "-cp",
      FI_JVM_BASE + "/" + PLUGIN_PATH,
      CGRAPH_STR,
      jarfile_str,
      target_class.replace(".class", ""),
      "fuzzerTestOneInput", # entrymethod
      "jdk.:java.:javax.:sun.:sunw.:com.sun.:com.ibm.:com.apple.:apple.awt." # exclude prefix
  ]

  print("Running command: [%s]" % " ".join(cmd))
  subprocess.check_call(" ".join(cmd), shell=True)


def run_analysis(path):
  if not build_jvm_frontend():
    return False

  currwd = os.getcwd()
  os.chdir(path)

  targets, jar_files = find_fuzz_targets(path)
  for (classfile, wrapper_script, jar_file) in targets:
    run_introspector_frontend(classfile, jar_files)

  os.chdir(currwd)

if __name__ == "__main__":
  if 'MVN' in os.environ:
    target_mvn = os.environ['MVN']
  currdir = os.getcwd()
  mydir = os.path.dirname(os.path.abspath(__file__))
  os.chdir(mydir)

  run_analysis("/out/")

  os.chdir(currdir)
