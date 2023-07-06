# Copyright 2023 Fuzz Introspector Authors
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

# License for bash script or python file
BASH_LICENSE = """
# Copyright 2023 Google LLC
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
#
##########################################################################"""

# License for java file
JVM_LICENSE = """// Copyright 2023 Google LLC
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
//
///////////////////////////////////////////////////////////////////////////"""


def gen_dockerfile(github_url, project_name, language="python"):
    if language == "python":
        return gen_dockerfile_python(github_url, project_name)
    elif language == "jvm":
        return gen_dockerfile_jvm(github_url, project_name)
    else:
        return None


def gen_builder_1(language="python"):
    if language == "python":
        return gen_builder_1_python()
    elif language == "jvm":
        return gen_builder_1_jvm()
    else:
        return None


def gen_base_fuzzer(language="python"):
    if language == "python":
        return gen_base_fuzzer_python()
    elif language == "jvm":
        return gen_base_fuzzer_jvm()
    else:
        return None


def gen_project_yaml(github_url, language="python"):
    BASE_YAML = """fuzzing_engines:
- libfuzzer
homepage: %s
language: %s
main_repo: %s
sanitizers:
- address
- undefined
primary_contacts: autofuzz@fuzz-introspector.com""" % (github_url, language,
                                                       github_url)

    return BASE_YAML


def gen_dockerfile_python(github_url, project_name):
    DOCKER_LICENSE = "#!/usr/bin/python3\n" + BASH_LICENSE
    DOCKER_STEPS = """FROM gcr.io/oss-fuzz-base/base-builder-python
#RUN pip3 install --upgrade pip && pip3 install cython
#RUN git clone %s %s
COPY %s %s
COPY *.sh *py $SRC/
WORKDIR $SRC/%s
""" % (github_url, project_name, project_name, project_name, project_name)

    return DOCKER_LICENSE + "\n" + DOCKER_STEPS


def gen_dockerfile_jvm(github_url, project_name):
    DOCKER_STEPS = """FROM gcr.io/oss-fuzz-base/base-builder-jvm
#RUN curl -L https://archive.apache.org/dist/maven/maven-3/3.6.3/binaries/apache-maven-3.6.3-bin.zip -o maven.zip && unzip maven.zip -d $SRC/maven && rm -rf maven.zip
COPY ant.zip $SRC/ant.zip
COPY maven.zip $SRC/maven.zip
COPY gradle.zip $SRC/gradle.zip
COPY protoc.zip $SRC/protoc.zip
RUN unzip ant.zip -d $SRC/ant && rm ./ant.zip
RUN unzip maven.zip -d $SRC/maven && rm ./maven.zip
RUN unzip gradle.zip -d $SRC/gradle && rm ./gradle.zip
RUN mkdir -p $SRC/protoc
RUN unzip protoc.zip -d $SRC/protoc && rm ./protoc.zip
ENV ANT $SRC/ant/apache-ant-1.9.16/bin/ant
ENV MVN $SRC/maven/apache-maven-3.6.3/bin/mvn
ENV GRADLE_HOME $SRC/gradle/gradle-7.4.2
ENV PATH="$SRC/gradle/gradle-7.4.2/bin:$SRC/protoc/bin:$PATH"
#RUN git clone --depth 1 %s %s
COPY %s %s
COPY *.sh *.java $SRC/
WORKDIR $SRC/%s
""" % (github_url, project_name, project_name, project_name, project_name)

    return BASH_LICENSE + "\n" + DOCKER_STEPS


def gen_builder_1_python():
    BUILD_LICENSE = "#!/bin/bash -eu\n" + BASH_LICENSE
    BUILD_SCRIPT = """pip3 install .
# Build fuzzers in $OUT.
for fuzzer in $(find $SRC -name 'fuzz_*.py'); do
  compile_python_fuzzer $fuzzer
done"""

    return BUILD_LICENSE + "\n" + BUILD_SCRIPT


def gen_builder_1_jvm():
    BUILD_LICENSE = "#!/bin/bash -eu\n" + BASH_LICENSE
    BUILD_SCRIPT = """SUCCESS=false
BASEDIR=$(pwd)
for dir in $(ls -R)
do
  cd $BASEDIR
  if [[ $dir == *: ]]
  then
    dir=${dir%*:}
    cd $dir
    chmod +x $SRC/protoc/bin/protoc
    if test -f "pom.xml"
    then
      find ./ -name pom.xml -exec sed -i 's/compilerVersion>1.5</compilerVersion>1.8</g' {} \;
      find ./ -name pom.xml -exec sed -i 's/compilerVersion>1.6</compilerVersion>1.8</g' {} \;
      find ./ -name pom.xml -exec sed -i 's/source>1.5</source>1.8</g' {} \;
      find ./ -name pom.xml -exec sed -i 's/source>1.6</source>1.8</g' {} \;
      find ./ -name pom.xml -exec sed -i 's/target>1.5</target>1.8</g' {} \;
      find ./ -name pom.xml -exec sed -i 's/target>1.6</target>1.8</g' {} \;
      find ./ -name pom.xml -exec sed -i 's/java15/java18/g' {} \;
      find ./ -name pom.xml -exec sed -i 's/java16/java18/g' {} \;
      find ./ -name pom.xml -exec sed -i 's/java-1.5/java-1.8/g' {} \;
      find ./ -name pom.xml -exec sed -i 's/java-1.6/java-1.8/g' {} \;
      MAVEN_ARGS="-Dmaven.test.skip=true --update-snapshots -Dmaven.javadoc.skip=true "
      MAVEN_ARGS=$MAVEN_ARGS"-Dpmd.skip=true -Dencoding=UTF-8 -Dmaven.antrun.skip=true"
      $MVN clean package dependency:copy-dependencies $MAVEN_ARGS
      SUCCESS=true
      break
    elif test -f "build.gradle" || test -f "build.gradle.kts"
    then
      chmod +x ./gradlew
      if ./gradlew tasks --all | grep -qw "^spotlessCheck"
      then
        ./gradlew clean build -x test -x spotlessCheck
      else
        ./gradlew clean build -x test
      fi
      ./gradlew --stop
      SUCCESS=true
      break
    elif test -f "build.xml"
    then
      $ANT
      SUCCESS=true
      break
    fi
  fi
done

if [ "$SUCCESS" = false ]
then
  echo "Unknown project type"
  exit 127
fi

cd $BASEDIR

JARFILE_LIST=
for JARFILE in $(find ./  -name *.jar)
do
  if [[ "$JARFILE" == *"target/"* ]] || [[ "$JARFILE" == *"build/"* ]]
  then
    if [[ "$JARFILE" != *sources.jar ]] && [[ "$JARFILE" != *javadoc.jar ]]
    then
      cp $JARFILE $OUT/
      JARFILE_LIST="$JARFILE_LIST$(basename $JARFILE) "
    fi
  fi
done

curr_dir=$(pwd)
rm -rf $OUT/jar_temp
mkdir $OUT/jar_temp
cd $OUT/jar_temp
for JARFILE in $JARFILE_LIST
do
  jar -xf $OUT/$JARFILE
done
cd $curr_dir

# Retrieve apache-common-lang3 library
# This library provides method to translate primitive type arrays to
# their respective class object arrays to avoid compilation error.
wget -P $OUT/ https://repo1.maven.org/maven2/org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.jar

BUILD_CLASSPATH=$JAZZER_API_PATH:$OUT/jar_temp:$OUT/commons-lang3-3.12.0.jar
RUNTIME_CLASSPATH=\$this_dir/jar_temp:\$this_dir/commons-lang3-3.12.0.jar:\$this_dir

for fuzzer in $(find $SRC -name 'Fuzz.java')
do
  fuzzer_basename=$(basename -s .java $fuzzer)
  javac -cp $BUILD_CLASSPATH $fuzzer
  cp $SRC/$fuzzer_basename.class $OUT/

  # Create an execution wrapper that executes Jazzer with the correct arguments.
  echo "#!/bin/bash

  # LLVMFuzzerTestOneInput for fuzzer detection.
  this_dir=\$(dirname \"\$0\")
  if [[ \"\$@\" =~ (^| )-runs=[0-9]+($| ) ]]
  then
    mem_settings='-Xmx1900m:-Xss900k'
  else
    mem_settings='-Xmx2048m:-Xss1024k'
  fi

  LD_LIBRARY_PATH=\"$JVM_LD_LIBRARY_PATH\":\$this_dir \
    \$this_dir/jazzer_driver --agent_path=\$this_dir/jazzer_agent_deploy.jar \
    --cp=$RUNTIME_CLASSPATH \
    --target_class=$fuzzer_basename \
    --jvm_args=\"\$mem_settings\" \
    \$@" > $OUT/$fuzzer_basename
    chmod u+x $OUT/$fuzzer_basename
done"""

    return BUILD_LICENSE + "\n" + BUILD_SCRIPT


def gen_base_fuzzer_python():
    BASE_LICENSE = "#!/usr/bin/python3\n" + BASH_LICENSE
    BASE_FUZZER = """import sys
import atheris


@atheris.instrument_func
def TestOneInput(data):
  fdp = atheris.FuzzedDataProvider(data)


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput)
  atheris.Fuzz()


if __name__ == "__main__":
  main()"""

    return BASE_LICENSE + "\n" + BASE_FUZZER


def gen_base_fuzzer_jvm(need_base_import=True):
    BASE_IMPORT = """import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import org.apache.commons.lang3.ArrayUtils;"""
    BASE_FUZZER = """/*IMPORTS*/
public class Fuzz/*COUNTER*/ {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
/*STATIC_OBJECT_CHOICE*/
/*CODE*/
  }
}"""

    if need_base_import:
        return JVM_LICENSE + "\n" + BASE_IMPORT + BASE_FUZZER
    else:
        return JVM_LICENSE + "\n" + BASE_FUZZER
