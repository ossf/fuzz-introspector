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

from app.site.models import *

TEST_PROJECTS = [
  Project(name='name1', language='python', fuzz_count=3, reach="25.5%", runtime_cov="32.6%"),
  Project(name='name2', language='python', fuzz_count=3, reach="25.5%", runtime_cov="32.6%"),
  Project(name='name3', language='python', fuzz_count=3, reach="25.5%", runtime_cov="32.6%"),
  Project(name='name4', language='python', fuzz_count=3, reach="25.5%", runtime_cov="32.6%"),
  Project(name='name5', language='java', fuzz_count=3, reach="25.5%", runtime_cov="32.6%"),
  Project(name='name6', language='java', fuzz_count=3, reach="25.5%", runtime_cov="32.6%"),
  Project(name='name7', language='java', fuzz_count=3, reach="25.5%", runtime_cov="32.6%"),
  Project(name='name8', language='c++', fuzz_count=3, reach="25.5%", runtime_cov="32.6%"),
  Project(name='name9', language='c++', fuzz_count=3, reach="25.5%", runtime_cov="32.6%"),
  Project(name='name10', language='c', fuzz_count=3, reach="25.5%", runtime_cov="32.6%"),
  Project(name='name11', language='c', fuzz_count=3, reach="25.5%", runtime_cov="32.6%"),
  Project(name='name12', language='c', fuzz_count=3, reach="25.5%", runtime_cov="32.6%"),
  Project(name='name13', language='c', fuzz_count=3, reach="25.5%", runtime_cov="32.6%"),
]

TEST_FUNCTIONS = [
	Function(name="function name1", project=TEST_PROJECTS[0]),
  Function(name="function name2", project=TEST_PROJECTS[0]),
  Function(name="function name3", project=TEST_PROJECTS[0]),
  Function(name="function name4", project=TEST_PROJECTS[0]),
  Function(name="function name5", project=TEST_PROJECTS[0]),
  Function(name="function name6", project=TEST_PROJECTS[0]),
  Function(name="function name7", project=TEST_PROJECTS[0]),
]

def get_projects():
	return TEST_PROJECTS

def get_functions():
	return TEST_FUNCTIONS