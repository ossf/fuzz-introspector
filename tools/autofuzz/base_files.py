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


def gen_dockerfile(github_url, project_name):
    DOCKER_LICENSE = """#!/usr/bin/python3
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
# limitations under the License."""

    DOCKER_STEPS = """FROM gcr.io/oss-fuzz-base/base-builder-python
#RUN pip3 install --upgrade pip && pip3 install cython
#RUN git clone %s %s
COPY %s %s
COPY *.sh *py $SRC/
WORKDIR $SRC/%s
""" % (github_url, project_name, project_name, project_name, project_name)

    return DOCKER_LICENSE + "\n" + DOCKER_STEPS


def gen_builder_1():
    BUILD_LICENSE = """#!/bin/bash -eu
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
################################################################################"""

    BUILD_SCRIPT = """pip3 install .
# Build fuzzers in $OUT.
for fuzzer in $(find $SRC -name 'fuzz_*.py'); do
  compile_python_fuzzer $fuzzer
done"""

    return BUILD_LICENSE + "\n" + BUILD_SCRIPT


def gen_project_yaml(github_url):
    BASE_YAML = """fuzzing_engines:
- libfuzzer
homepage: %s
language: python
main_repo: %s
sanitizers:
- address
- undefined
primary_contants: autofuzz@fuzz-introspector.com""" % (github_url, github_url)

    return BASE_YAML


def gen_base_fuzzer():
    BASE_LICENSE = """#!/usr/bin/python3
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
# limitations under the License."""

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
