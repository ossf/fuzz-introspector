#!/usr/bin/python3

import requests
import shutil
import json
import os

def download_file(link):
    try:
        return requests.get(link).text
    except:
        return None

with open(".proj_link") as f:
    link_map = json.loads(f.read())

if os.path.exists("all_functions"):
    shutil.rmtree("all_functions")
if os.path.exists("summary_json"):
    shutil.rmtree("summary_json")

os.mkdir("all_funtions")
os.mkdir("summary_json")

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
                f.write(fs_json)

os.remove(".proj_link")
