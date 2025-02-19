#!/bin/bash
# Copyright 2022 Fuzz Introspector Authors
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
################################################################################
set -Eeuo pipefail

set -x

# this currently fails
# echo "pep8"
# pep8 --first ./src/

# flake8 based on https://github.com/py-actions/flake8/blob/777f3c125938bc6e01d737c6306ecee8728cff24/src/index.js
echo "flake8 check post process"
(cd src/ && flake8 --ignore E125,W503,W504,W605 --max-line-length 100)

echo "flake8 check python frontend"
(cd frontends/python/ && flake8 --ignore E125,W503,W504,W605 --max-line-length 100)

echo "yapf code formatting"
(yapf -d -r ./src/fuzz_introspector/)
(yapf -d -r ./tools/auto-fuzz)
(yapf -d -r ./tools/web-fuzzing-introspection/app/webapp/)
(yapf -d ./tools/web-fuzzing-introspection/app/*.py)
# Ignore directories created when running launch_*_oss_fuzz.
(yapf -d -r ./tools/web-fuzzing-introspection/app/static/assets/db \
  -e tools/web-fuzzing-introspection/app/static/assets/db/oss-fuzz-clone \
  -e tools/web-fuzzing-introspection/app/static/assets/db/db-projects \
)

echo "pylint"
(cd src && pylint --recursive=y fuzz_introspector main.py || true)

echo "mypy"
(cd src && mypy --ignore-missing-imports -m main)
(cd tools/web-fuzzing-introspection && mypy --ignore-missing-imports --explicit-package-bases --exclude app/static/assets/db/oss-fuzz-clone/ .)
