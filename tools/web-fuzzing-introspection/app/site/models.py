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

class DBSummary:
    def __init__(self, all_projects, total_number_of_projects, total_fuzzers, total_functions, language_count):
        self.all_projects = all_projects
        self.total_number_of_projects = total_number_of_projects
        self.total_fuzzers = total_fuzzers
        self.total_functions = total_functions
        self.language_count = language_count

class Project:
    def __init__(self, name, language, fuzz_count, reach, runtime_cov):
        self.name = name
        self.language = language
        self.fuzz_count = fuzz_count
        self.reach = reach
        self.runtime_cov = runtime_cov

class Function:
    def __init__(self, name, project, is_reached=False, runtime_code_coverage = 32.4):
        self.name = name
        self.project = project
        self.is_reached = is_reached
        self.runtime_code_coverage = runtime_code_coverage