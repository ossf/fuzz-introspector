#!/usr/bin/env python
# Copyright 2024 Fuzz Introspector Authors
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
import os
import requests
import subprocess

PROJECTS = [
    'wrong-project-name', 'htslib', 'icu', 'tinyxml2', 'leveldb',
    'eigen', 'immer', 'fluent-bit', 'json-java', 'java-diff-utils'
]
APIS = [
    '/api/annotated-cfg', '/api/project-summary', '/api/branch-blockers',
    '/api/all-functions', '/api/all-jvm-constructors',
    '/api/easy-params-far-reach', '/api/far-reach-low-cov-fuzz-keyword',
    '/api/project-repository', '/api/far-reach-but-low-coverage',
    '/api/all-header-files'
]
BASE_URL = 'http://localhost:8080'

def _test_server_api(url):
  """Function for calling server API and check if the return code is 2XX or 3XX
     The call is considered fail if the return code is 4XX or 5XX.
  """
  response = requests.get(url)

  if response.status_code >= 400 or response.status_code < 200:
    print(f'{url} failed with return code: {response.status_code}')
    raise Exception(f'{url} failed with return code: {response.status_code}')


if __name__ == "__main__":
  ROOT_FI = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..')

  code = subprocess.call([os.path.join(ROOT_FI, '.github', 'helper', 'prepare_webapp')])
  if code:
    raise Exception('Failed to prepare the webapp for testing.')

  # A list of curl test to the webapp api
  for project in PROJECTS:
    for api in APIS:
      _test_server_api(f'{BASE_URL}{api}?project={project}')

  # Shutdown started webserver
  print("Shutting down started webserver")
  try:
    requests.get('http://localhost:8080/api/shutdown')
  except:
    pass
