#!/usr/bin/python3

import os
import json

lang_list = ["c", "cpp", "python"]
#lang_list = ["jvm"]

function_map = dict()
fs_json_map = dict()

EMPTY_FS_JSON = '{"report": {"FuzzEngineInputAnalysis": {}, "SinkCoverageAnalyser": []}}'
SINK_LIST = ['system','execl','execlp','execle','execv','execvp','execve','wordexp',
             'popen','fdopen','exec','eval','call','run','Popen','check_output',
             'spawnlpe','spawnve','execlpe','execlpe','create_subprocess_shell',
             'create_subprocess_exec','run','sleep','listen','runsource','runcode',
             'write','push','interact','raw_input','interact','compile_command']

for lang in lang_list:
    with open(f"proj/{lang}") as f:
        proj_list = f.read()

    for proj in proj_list.split("\n"):
        if proj and os.path.exists(f"all_functions/{proj}"):
            with open(f"all_functions/{proj}") as f:
                func_list = json.loads(f.read().split("=", 1)[1])
            list = []
            for func in func_list:
                func_name = func["Func name"].split("\n")[1].lstrip(" ").rstrip(" ")
                func_name = func_name.rsplit(".", 1)[-1]
                if lang == "jvm":
                    func_name = func_name.split("(", 1)[0]
                if func_name in SINK_LIST:
                    list.append(func_name)
            function_map[proj] = list

        if proj and os.path.exists(f"summary_json/{proj}"):
            with open(f"summary_json/{proj}") as f:
                fs_str = f.read()
            if fs_str != EMPTY_FS_JSON:
                list = []
                try:
                    map = json.loads(fs_str)
                except:
                    continue
                if "analyses" in map.keys():
                    for item in map['analyses']['SinkCoverageAnalyser']:
                        list.append(item['func_name'])
                fs_json_map[proj] = list

with open("func_result.csv", "w") as f:
    f.write("Project,Sink Functions\n")
    for key in function_map.keys():
        for item in function_map[key]:
            f.write(f"{key},{item}\n")

with open("sink_analyser_result", "w") as f:
    f.write("Project,Sink Functions\n")
    for key in function_map.keys():
        for item in function_map[key]:
            f.write(f"{key},{item}\n")
