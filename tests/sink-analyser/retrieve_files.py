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
import json

def download_file(link):
    try:
        return requests.get(link).text
    except:
        return None

with open(".proj_link") as f:
    link_map = json.loads(f.read())

for proj in link_map.keys():
    link = link_map[proj]
    print(f"Handling project: {proj}. Base link: {link}")
    all_functions = download_file(f"{link}/all_functions.js")
    summary_json = download_file(f"{link}/summary.json")
    if all_functions:
        with open(f"all_functions/{proj}", "w") as f:
            f.write(all_functions)
        if summary_json:
            with open(f"summary_json/{proj}", "w") as f:
                f.write(summary_json)
