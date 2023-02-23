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

git_repos = {
    'python': [
        # 'https://github.com/davidhalter/parso',
        'https://github.com/nvawda/bz2file',
        # 'https://github.com/executablebooks/markdown-it-py'
    ],
    'jvm': [
        'https://github.com/eclipse-ee4j/angus-mail',
        # 'https://github.com/jboss-javassist/javassist'
    ]
}
