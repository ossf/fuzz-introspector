#!/usr/bin/python3

import requests
import lxml.html
import json

data = requests.get('https://oss-fuzz-introspector.storage.googleapis.com/index.html').text
html = lxml.html.fromstring(data)

link_map = dict()
for li in html.getchildren()[1].getchildren()[2]:
    link_item = li.getchildren()[0]
    proj = link_item.text.replace('\n', '').lstrip(' ').rstrip(' ')
    link = link_item.get('href').rsplit('/', 1)[0]
    link_map[proj] = link

with open(".proj_link", "w") as f:
    f.write(json.dumps(link_map))
