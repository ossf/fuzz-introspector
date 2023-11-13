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
##########################################################################
FROM ubuntu:22.04@sha256:2b7412e6465c3c7fc5bb21d3e6f1917c167358449fecac8176c6e496e5c1f05f

RUN apt-get update && \
    apt-get install pip git -y

ENV SRC /src
ENV OUT /out

RUN mkdir -p $SRC && \
    mkdir -p $OUT

COPY fuzz-introspector $SRC/fuzz-introspector
COPY work $SRC/work

RUN cd $SRC/fuzz-introspector && \
    git submodule init && \
    git submodule update && \
    pip3 install -r ./requirements.txt

WORKDIR $SRC/fuzz-introspector/tools/auto-fuzz
