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
##########################################################################
FROM ubuntu:22.04

RUN apt-get update && apt-get install git pip curl -y

RUN curl -sSL https://get.docker.com/ | sh
RUN git clone https://github.com/ossf/fuzz-introspector fuzz-introspector

WORKDIR $SRC/fuzz-introspector
RUN git submodule init
RUN git submodule update

RUN pip3 install --upgrade pip
RUN pip3 install -r ./requirements.txt
WORKDIR $SRC/fuzz-introspector/frontends/python/PyCG
RUN pip3 install .

WORKDIR $SRC/fuzz-introspector/tools/auto-fuzz/
