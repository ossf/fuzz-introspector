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

MAX_FUZZERS_PER_PROJECT = 400
MAX_TARGET_PER_PROJECT_HEURISTIC = 1000
MAX_THREADS = 4

BATCH_SIZE_BEFORE_DOCKER_CLEAN = 40

JDK_URL = {
    "jdk15":
    "https://download.java.net/java/GA/jdk15.0.2/0d1cfde4252546c6931946de8db48ee2/7/GPL/openjdk-15.0.2_linux-x64_bin.tar.gz",
    "jdk17":
    "https://download.java.net/openjdk/jdk17/ri/openjdk-17+35_linux-x64_bin.tar.gz",
    "jdk11":
    "https://download.java.net/openjdk/jdk11.0.0.1/ri/openjdk-11.0.0.1_linux-x64_bin.tar.gz",
    "jdk8":
    "https://download.java.net/openjdk/jdk8u43/ri/openjdk-8u43-linux-x64.tar.gz"
}
ANT_URL = "https://dlcdn.apache.org//ant/binaries/apache-ant-1.10.13-bin.zip"
MAVEN_URL = "https://archive.apache.org/dist/maven/maven-3/3.6.3/binaries/apache-maven-3.6.3-bin.zip"
GRADLE_URL = "https://services.gradle.org/distributions/gradle-7.4.2-bin.zip"
PROTOC_URL = "https://github.com/protocolbuffers/protobuf/releases/download/v3.15.8/protoc-3.15.8-linux-x86_64.zip"

JDK_HOME = {
    "jdk15": "jdk-15.0.2",
    "jdk17": "jdk-17",
    "jdk11": "jdk-11.0.0.1",
    "jdk8": "java-se-8u43-ri"
}
ANT_PATH = "apache-ant-1.10.13/bin"
MAVEN_PATH = "apache-maven-3.6.3/bin"
GRADLE_HOME = "gradle-7.4.2"
GRADLE_PATH = f"{GRADLE_HOME}/bin"
PROTOC_PATH = "protoc/bin"

# This is an user-controlled options. If this is set to True, it will always
# search for all subclasses of a target class when the auto-fuzz generation
# handles object creation of the target class. Otherwise, the searching of
# subclasses will only happen when the the target class is not concrete.
SEARCH_SUBCLASS_FOR_OBJECT_CREATION = False

# These are user-controlled options. If any of them are set to True, the
# auto-fuzz generation process for java will ignore some targets methods
# which does not have much fuzzing value. Otherwise, those methods will
# be included in the generation result
# JAVA_IGNORE_GETTER_SETTER: All getters, setters and boolean checking methods.
# JAVA_IGNORE_PLAIN_METHOD: Methods without parameters.
# JAVA_IGNORE_TEST_METHOD: Methods that belongs to fuzzing engine or unit testing engine.
# JAVA_IGNORE_GENERAL_METHOD: Methods that are inherited from the Object class.
JAVA_IGNORE_GETTER_SETTER = True
JAVA_IGNORE_PLAIN_METHOD = True
JAVA_IGNORE_TEST_METHOD = True
JAVA_IGNORE_OBJECT_METHOD = True

git_repos = {
    'python': [
        # 'https://github.com/davidhalter/parso',
        'https://github.com/nvawda/bz2file',
        # 'https://github.com/executablebooks/markdown-it-py'
    ],
    'jvm': [
        # 'https://github.com/eclipse-ee4j/angus-mail',
        # 'https://github.com/jboss-javassist/javassist'
        'https://github.com/tukaani-project/xz-java'
    ]
}

benchmark = {
    'jvm': [
        'benchmark1', 'benchmark2', 'benchmark3', 'benchmark4', 'benchmark5',
        'benchmark6', 'benchmark7', 'benchmark8'
    ]
}
