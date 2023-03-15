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

MAX_FUZZERS_PER_PROJECT = 10
MAX_TARGET_PER_PROJECT_HEURISTIC = 100
MAX_THREADS = 4

BATCH_SIZE_BEFORE_DOCKER_CLEAN = 40

ANT_URL = "https://dlcdn.apache.org//ant/binaries/apache-ant-1.9.16-bin.zip"
MAVEN_URL = "https://downloads.apache.org/maven/maven-3/3.6.3/binaries/apache-maven-3.6.3-bin.zip"
GRADLE_URL = "https://services.gradle.org/distributions/gradle-7.4.2-bin.zip"

ANT_PATH = "apache-ant-1.9.16/bin"
MAVEN_PATH = "apache-maven-3.6.3/bin"
GRADLE_HOME = "gradle-7.4.2"
GRADLE_PATH = f"{GRADLE_HOME}/bin"

# This is an user-controlled optios. If this is set to True, it will always
# search for all subclasses of a target class when the auto-fuzz generation
# handles object creation of the target class. Otherwise, the searching of
# subclasses will only happen when the the target class is not concrete.
SEARCH_SUBCLASS_FOR_OBJECT_CREATION = False

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
