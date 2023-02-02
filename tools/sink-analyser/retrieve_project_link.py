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
#!/usr/bin/python3

import requests
import lxml.html
import json

data = requests.get('https://oss-fuzz-introspector.storage.googleapis.com/index.html').text
html = lxml.html.fromstring(data)

link_map = dict()
for tr in html.find_class("table-wrapper")[0].getchildren()[0].getchildren()[1]:
    link_item = tr.getchildren()[0].getchildren()[0]
    proj = link_item.text.lstrip(' ').rstrip(' ')
    link = link_item.get('href').rsplit('/', 1)[0]
    link_map[proj] = link

with open(".proj_link", "w") as f:
    f.write(json.dumps(link_map))
