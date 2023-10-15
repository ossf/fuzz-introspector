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
import constants
import os


def gen_dockerfile(github_url,
                   project_name,
                   language="python",
                   jdk_version="jdk15",
                   build_project=True,
                   project_build_type=None):
    template_dir = _get_template_directory(language, project_build_type)

    if not template_dir:
        return ""

    if language == "python":
        return _gen_dockerfile_python(github_url, project_name, template_dir)
    elif language == "java":
        return _gen_dockerfile_java(github_url, project_name, jdk_version,
                                    build_project, template_dir,
                                    project_build_type)
    else:
        return ""


def gen_builder_1(language="python",
                  project_build_type=None,
                  build_project=True):
    template_dir = _get_template_directory(language, project_build_type)

    if not template_dir:
        return ""

    if language == "python":
        return _gen_builder_1_python(template_dir)
    elif language == "java":
        return _gen_builder_1_java(template_dir, build_project)
    else:
        return ""


def gen_base_fuzzer(language="python",
                    project_build_type=None,
                    need_base_import=True):
    template_dir = _get_template_directory(language, project_build_type)

    if not template_dir:
        return ""

    if language == "python":
        return _gen_base_fuzzer_python(template_dir)
    elif language == "java":
        return _gen_base_fuzzer_java(template_dir, need_base_import)
    else:
        return ""


def gen_project_yaml(github_url, language="python", project_build_type=None):
    template_dir = _get_template_directory(language, project_build_type)

    if not template_dir:
        return ""

    with open(os.path.join(template_dir, "project.yaml"), "r") as file:
        BASE_YAML = file.read() % (github_url, github_url)

    return BASE_YAML


def _gen_dockerfile_python(github_url, project_name, template_dir):
    with open(os.path.join(template_dir, "Dockerfile-template"), "r") as file:
        BASE_DOCKERFILE = file.read() % (
            github_url, project_name, project_name, project_name, project_name)

    return BASE_DOCKERFILE


def _gen_dockerfile_java(github_url, project_name, jdk_version, build_project,
                         template_dir, project_build_type):
    if build_project:
        comment = "#"
    else:
        comment = ""

    with open(os.path.join(template_dir, "Dockerfile-template"), "r") as file:
        BASE_DOCKERFILE = file.read() % (
            "%s", constants.FILE_TO_PREPARE['java']['protoc'],
            constants.JDK_URL[jdk_version], constants.JDK_HOME[jdk_version],
            github_url, project_name, project_name, project_name, comment,
            comment, project_name)

    if project_build_type in constants.FILE_TO_PREPARE['java']:
        return BASE_DOCKERFILE % (
            constants.FILE_TO_PREPARE['java'][project_build_type])
    else:
        return ""


def _gen_builder_1_python(template_dir):
    with open(os.path.join(template_dir, "build.sh-template"), "r") as file:
        BASE_BUILDER = "#!/bin/bash -eu\n" + file.read()

    return BASE_BUILDER


def _gen_builder_1_java(template_dir, build_project):
    with open(os.path.join(template_dir, "build.sh-template"), "r") as file:
        BASE_BUILDER = "#!/bin/bash -eu\n" + file.read()

    if build_project:
        return BASE_BUILDER % ("", "", ": <<'COMMENT'", "COMMENT")
    else:
        return BASE_BUILDER % (": <<'COMMENT'", "COMMENT", "", "")


def _gen_base_fuzzer_python(template_dir):
    with open(os.path.join(template_dir, "fuzz_1.py"), "r") as file:
        BASE_FUZZER = file.read()

    return BASE_FUZZER


def _gen_base_fuzzer_java(template_dir, need_base_import):
    BASE_IMPORT = """import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import org.apache.commons.lang3.ArrayUtils;"""

    with open(os.path.join(template_dir, "Fuzz.java"), "r") as file:
        BASE_FUZZER = file.read()

    if need_base_import:
        return BASE_FUZZER % (BASE_IMPORT)
    else:
        return BASE_FUZZER % ("")


def _get_template_directory(language, project_build_type):
    base_path = os.path.join(os.getcwd(), "templates")

    if project_build_type:
        path = os.path.join(base_path, language + "-" + project_build_type)
    else:
        path = os.path.join(base_path, language)

    if os.path.isdir(path):
        return os.path.abspath(path)
    else:
        return None
