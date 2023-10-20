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

import os
import sys

sys.path.append('..')
from templates import base_files


class OSS_FUZZ_PROJECT:
    """Abstraction of OSS-Fuzz project.

    Provides helper methods for easily managing files and folders and
    operations on a given OSS-Fuzz project.
    """

    def __init__(self, project_folder, github_url, language, benchmark=False):
        self.project_folder = project_folder
        self.github_url = github_url
        self.language = language
        self.benchmark = benchmark

    @property
    def build_script(self):
        return self.project_folder + "/build.sh"

    @property
    def dockerfile(self):
        return self.project_folder + "/Dockerfile"

    @property
    def project_yaml(self):
        return self.project_folder + "/project.yaml"

    @property
    def base_fuzzer(self):
        if self.language == "python":
            return self.project_folder + "/fuzz_1.py"
        elif self.language == "java":
            return self.project_folder + "/Fuzz.java"
        else:
            # Temporary fail safe logic
            return self.project_folder + "/fuzz_1.py"

    @property
    def oss_fuzz_project_name(self):
        return os.path.basename(self.project_folder)

    @property
    def oss_fuzz_fuzzer_namer(self):
        if self.language == "python":
            return os.path.basename(self.base_fuzzer).replace(".py", "")
        elif self.language == "java":
            return os.path.basename(self.base_fuzzer).replace(".java", "")
        else:
            # Temporary fail safe logic
            return os.path.basename(self.base_fuzzer).replace(".py", "")

    @property
    def project_name(self):
        if self.benchmark:
            return "%s-%s" % (self.language, self.github_url)
        else:
            # Simplify url by cutting https out, then assume what we have left is:
            # HTTP Type
            # github.com/{user}/{proj_name}
            # or
            # SSH Type
            # git@github.com:{user}/{proj_name}
            if self.github_url.startswith("https://"):
                return self.github_url.replace("https://", "").split("/")[2]
            elif self.github_url.startswith("http://"):
                return self.github_url.replace("http://", "").split("/")[2]
            else:
                return self.github_url.split("/")[1]

    def write_basefiles(self, project_build_type=None):
        with open(self.build_script, "w") as builder_file:
            builder_file.write(
                base_files.gen_builder_1(self.language, project_build_type))

        with open(self.base_fuzzer, "w") as fuzzer_file:
            fuzzer_file.write(
                base_files.gen_base_fuzzer(self.language, project_build_type))

        with open(self.project_yaml, "w") as yaml_file:
            yaml_file.write(
                base_files.gen_project_yaml(self.github_url, self.language,
                                            project_build_type))

        with open(self.dockerfile, "w") as docker_file:
            docker_file.write(
                base_files.gen_dockerfile(
                    self.github_url,
                    self.project_name,
                    self.language,
                    project_build_type=project_build_type))

    def change_java_dockerfile(self,
                               jdk_version,
                               project_build_type,
                               build_project=True):
        with open(self.dockerfile, "w") as docker_file:
            docker_file.write(
                base_files.gen_dockerfile(
                    self.github_url,
                    self.project_name,
                    self.language,
                    jdk_version,
                    build_project,
                    project_build_type=project_build_type))

    def change_build_script(self, project_build_type, build_project=True):
        with open(self.build_script, "w") as builder_file:
            builder_file.write(
                base_files.gen_builder_1(self.language, project_build_type,
                                         build_project))
