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
"""Script to make it easy testing API functionality locally"""

import requests
import json
import sys
import os

API_ENDPOINT = 'http://localhost:8080/api'
#API_ENDPOINT='https://introspector.oss-fuzz.com/api'

target_project = 'opencv'

targets = [
    'perfetto', 'pffft', 'phmap', 'simdutf', 'skcms', 'sleuthkit', 'snappy',
    'spdlog', 'speex', 'spice-usbredir', 'sql-parser', 'sqlite3', 'stb',
    'strongswan', 'tesseract-ocr', 'tidy-html5', 'tinygltf', 'tinyobjloader',
    'tinyusb', 'tinyxml2', 'tor', 'tpm2', 'tpm2-tss', 'tremor', 'unicorn',
    'unrar', 'uriparser', 'usbguard', 'uwebsockets', 'valijson', 'vorbis',
    'wabt', 'wavpack', 'wget', 'wget2'
]
# targets = ['perfetto', 'pffft', 'phmap', 'simdutf', 'skcms', 'sleuthkit', 'snappy', 'uriparser','uwebsockets', 'valijson']

targets = [
    'tinyxml2', 'htslib', 'icu', 'uriparser', 'opencv', 'tpm2', 'sql-parser'
]
#targets = ['sql-parser']
#targets = ['tinyxml2']
for target_project in targets:
    print("[+] Getting far reached funcs")
    far_reached = json.loads(
        requests.get(
            f'{API_ENDPOINT}/far-reach-but-low-coverage?project={target_project}',
            timeout=15).text)

    print("[+] Top function 20 target function:")
    #print(json.dumps(far_reached, indent=2))
    #continue
    #sys.exit(0)
    #top_func_name = far_reached['functions'][25]['raw_function_name']
    for i in range(10):
        print(">>>> New target" * 10)
        try:
            func_signature = far_reached['functions'][i]['function_signature']
            top_func_name = far_reached['functions'][i]['raw_function_name']
        except:
            continue
        print(f"- {func_signature}")

        #print(f"[+] Source code of {top_func_name}")
        source_url = f'{API_ENDPOINT}/function-source-code?project={target_project}&function_signature={func_signature}'
        print(f"URL: {source_url}")
        #print(requests.get(source_url, timeout=120).text)
        print("Source code")
        print(">" * 25)
        try:
            function_source = json.loads(
                requests.get(source_url, timeout=120).text)['source']
        except KeyError:
            continue
        print(function_source)
        print("<" * 25)
        #continue

        xref_url = f'{API_ENDPOINT}/all-cross-references?project={target_project}&function_signature={func_signature}'
        #print(f"[+] Getting cross-references of {top_func_name}")
        callsites = json.loads(requests.get(xref_url,
                                            timeout=5).text)['callsites']

        print("Cross-references:")
        for xref in callsites:
            print('-' * 30)
            print(
                f"src_func: {xref['src_func']}, src_file: {xref['filename']}, linenumber: {xref['cs_linenumber']}"
            )

            # We an extract the full source of the src function, but let's only show a
            # few lines around the API
            begin_line = str(int(xref['cs_linenumber']) - 3)
            end_line = str(int(xref['cs_linenumber']) + 3)
            xref_source_url = f'{API_ENDPOINT}/project-source-code?project={target_project}&filepath={xref["filename"]}&begin_line={begin_line}&end_line={end_line}'
            print(xref_source_url)
            callsite_source = json.loads(
                requests.get(xref_source_url, timeout=5).text)['source_code']
            print(callsite_source)
        #continue
        print("Cross-reference done")

        print("[+] Function signature ")
        func_sig_url = f'{API_ENDPOINT}/function-signature?project={target_project}&function={top_func_name}'
        raw_req = requests.get(func_sig_url, timeout=5).text
        #print(raw_req)
        func_sig = json.loads(raw_req)['signature']
        print(func_sig)
