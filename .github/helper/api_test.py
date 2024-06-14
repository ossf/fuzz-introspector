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
import itertools
import os
import requests
import subprocess
import urllib.parse

DATA = {
    'project': [
        '', 'wrong-project-name', 'htslib', 'icu', 'tinyxml2', 'leveldb',
        'eigen', 'immer', 'fluent-bit', 'json-java', 'java-diff-utils',
    ],
    'function': [
        '', 'wrong-function-name', 'hts_flush', 'u_formatMessage_76',
        'tinyxml2::XMLElement::BoolText(bool)const', 'cb_trace'
        'leveldb::(anonymousnamespace)::DBIter::Prev()',
        'Eigen::Matrix<int,-1,1,0,-1,1>::~Matrix()',
        '[org.json.JSONArray].toString()',
        '[com.github.difflib.algorithm.Change].withEndOriginal(int)'
    ],
    'q': [
        '', 'c', 'java', 'json', 'random'
    ],
    'function_signature': [
        '', 'wrong-signature', 'hts_flush', 'u_formatMessage_76',
        'tinyxml2::XMLElement::BoolText(bool)const', 'cb_trace'
        'leveldb::(anonymousnamespace)::DBIter::Prev()',
        'Eigen::Matrix<int,-1,1,0,-1,1>::~Matrix()',
        '[org.json.JSONArray].toString()',
        '[com.github.difflib.algorithm.Change].withEndOriginal(int)'
    ]
}


APIS = {
    '/': {
        'args': []
    },
    '/function-profile': {
        'args': ['project', 'function']
    },
    '/project-profile': {
        'args': ['project']
    },
    '/function-search': {
        'args': ['q']
    },
    '/projects-overview': {
        'args': []
    },
    '/target_oracle': {
        'args': []
    },
    '/indexing-overview': {
        'args': []
    },
    '/about': {
        'args': []
    },
    '/api': {
        'args': []
    },
    '/api/annotated-cfg': {
        'args': ['project']
    },
    '/api/project-summary': {
        'args': ['project']
    },
    '/api/branch-blockers': {
        'args': ['project']
    },
    '/api/all-cross-references': {
        'args': ['project', 'function_signature']
    },
    '/api/all-functions': {
        'args': ['project']
    },
    '/api/all-jvm-constructors': {
        'args': ['project']
    },
    '/api/function-signature': {
        'args': ['project', 'function']
    },
    '/api/function-source-code': {
        'args': ['project', 'function_signature']
    },
    '/api/easy-params-far-reach': {
        'args': ['project']
    },
    '/api/far-reach-low-cov-fuzz-keyword': {
        'args': ['project']
    },
    '/api/project-repository': {
        'args': ['project']
    },
    '/api/project-repository': {
        'args': ['project']
    },
    '/api/far-reach-but-low-coverage': {
        'args': ['project']
    },
    '/api/all-header-files': {
        'args': ['project']
    },
    '/api/function-target-oracle': {
        'args': []
    },
    '/api/sample-cross-references': {
        'args': ['project', 'function_signature']
    }
}
BASE_URL = 'http://localhost:8080'
EXCEPTIONS = []


def _test_server_api(url):
  """Function for calling server API and check if the return code is 2XX or 3XX
     The call is considered fail if the return code is 4XX or 5XX.
  """
  response = requests.get(url)

  if response.status_code >= 400 or response.status_code < 200:
    print(f'{url} failed with return code: {response.status_code}')
    EXCEPTIONS.append(f'{url} failed with return code: {response.status_code}')


if __name__ == "__main__":
  ROOT_FI = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..')

  code = subprocess.call([os.path.join(ROOT_FI, '.github', 'helper', 'prepare_webapp')])
  if code:
    EXCEPTIONS.append('Failed to prepare the webapp for testing.')

  # A list of curl test to the webapp api
  for key in APIS:
    data_dict = APIS[key]
    url = f'{BASE_URL}{key}'

    args = []
    for arg in data_dict['args']:
        values = []
        for value in DATA[arg]:
            values.append(f'{arg}={urllib.parse.quote_plus(value)}')
        args.append(values)
    if args:
      arg_strs = list(map('&'.join, itertools.product(*args)))
    else:
      arg_strs = []

    if len(arg_strs) > 0:
      for arg_str in arg_strs:
        _test_server_api(f'{url}?{arg_str}')
    else:
      _test_server_api(url)

  # Shutdown started webserver
  print("Shutting down started webserver")
  try:
    requests.get('http://localhost:8080/api/shutdown')
  except:
    pass

  if EXCEPTIONS:
    raise Exception(f'Test error. Details: {EXCEPTIONS}')
