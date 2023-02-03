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

import os
import json

#lang_list = ["c", "cpp", "python"]
lang_list = ["jvm"]

function_map = dict()
fs_json_map = dict()

SINK_LIST = ['system','execl','execlp','execle','execv','execvp','execve','wordexp',
             'popen','fdopen','exec','eval','call','Popen','check_output',
             'spawnlpe','spawnve','execlpe','execlpe','create_subprocess_shell',
             'create_subprocess_exec','run','listen','runsource','runcode',
             'write','push','interact','raw_input','compile_command'
]
SINK_LIST_JVM = ['[java.lang.Runtime].exec',
                 '[javax.xml.xpath.XPath].compile',
                 '[javax.xml.xpath.XPath].evaluate',
                 '[java.lang.Thread].run',
                 '[java.lang.Runnable].run',
                 '[java.util.concurrent.Executor].execute',
                 '[java.util.concurrent.Callable].call',
                 '[java.lang.System].console',
                 '[java.lang.System].load',
                 '[java.lang.System].loadLibrary',
                 '[java.lang.System].mapLibraryName',
                 '[java.lang.System].runFinalization',
                 '[java.lang.System].setErr',
                 '[java.lang.System].setIn',
                 '[java.lang.System].setOut',
                 '[java.lang.System].setProperties',
                 '[java.lang.System].setProperty',
                 '[java.lang.System].setSecurityManager',
                 '[java.lang.ProcessBuilder].directory',
                 '[java.lang.ProcessBuilder].inheritIO',
                 '[java.lang.ProcessBuilder].command',
                 '[java.lang.ProcessBuilder].redirectError',
                 '[java.lang.ProcessBuilder].redirectErrorStream',
                 '[java.lang.ProcessBuilder].redirectInput',
                 '[java.lang.ProcessBuilder].redirectOutput',
                 '[java.lang.ProcessBuilder].start'
]

for lang in lang_list:
    with open(f"proj/{lang}") as f:
        proj_list = f.read()

    for proj in proj_list.split("\n"):
        if proj and os.path.exists(f"all_functions/{proj}"):
            with open(f"all_functions/{proj}") as f:
                func_list = json.loads(f.read().split("=", 1)[1])
            l = []
            for func in func_list:
                func_name = func["Func name"].split("\n")[1].lstrip(" ").rstrip(" ")
                if lang == "jvm":
                    item_list = SINK_LIST_JVM
                else:
                    func_name = func_name.rsplit(".", 1)[-1]
                    item_list = SINK_LIST
                if func_name in SINK_LIST:
                    l.append(func_name)
            function_map[proj] = list(set(l))

        if proj and os.path.exists(f"summary_json/{proj}"):
            with open(f"summary_json/{proj}") as f:
                fs_str = f.read()
            l = []
            try:
                map = json.loads(fs_str)
            except:
                continue
            if "analyses" in map.keys():
                for item in map['analyses']['SinkCoverageAnalyser']:
                    l.append(item['func_name'])
            fs_json_map[proj] = list(set(l))

with open("func_result.csv", "w") as f:
    f.write("Project,Sink Functions\n")
    for key in function_map.keys():
        for item in function_map[key]:
            f.write(f"{key},{item}\n")

with open("sink_analyser_result.csv", "w") as f:
    f.write("Project,Sink Functions\n")
    for key in fs_json_map.keys():
        for item in fs_json_map[key]:
            f.write(f"{key},{item}\n")
