# Copyright 2022 Fuzz Introspector Authors
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
"""Analysis plugin for introspection sinks of interest"""

import logging

from typing import (
    List,
    Tuple,
    Dict
)

from fuzz_introspector import analysis
from fuzz_introspector.datatypes import (
    project_profile,
    fuzzer_profile,
    function_profile
)

logger = logging.getLogger(name=__name__)

# Common sink functions / methods for different language implementation

SINK_FUNCTION = {
    'c-cpp': [
        ('', 'system'),
        ('', 'execl'),
        ('', 'execve')
    ],
    'python': [
        ('', 'exec'),
        ('', 'eval'),
        ('subprocess', 'call'),
        ('subprocess', 'run'),
        ('subprocess', 'Popen'),
        ('subprocess', 'check_output'),
        ('os', 'system'),
        ('os', 'popen'),
        ('os', 'spawnlpe'),
        ('os', 'spawnve'),
        ('os', 'execl'),
        ('os', 'execve'),
        ('asyncio', 'create_subprocess_shell'),
        ('asyncio', 'create_subprocess_exec'),
        ('asyncio', 'run'),
        ('asyncio', 'sleep'),
        ('logging.config', 'listen'),
        ('code.InteractiveInterpreter', 'runsource'),
        ('code.InteractiveInterpreter', 'runcode'),
        ('code.InteractiveInterpreter', 'write'),
        ('code.InteractiveConsole', 'push'),
        ('code.InteractiveConsole', 'interact'),
        ('code.InteractiveConsole', 'raw_input'),
        ('code', 'interact'),
        ('code', 'compile_command')
    ],
    'jvm': [
        ('java.lang.Runtime', 'exec'),
        ('javax.xml.xpath.XPath', 'compile'),
        ('javax.xml.xpath.XPath', 'evaluate'),
        ('java.lang.Thread', 'sleep'),
        ('java.lang.Thread', 'run'),
        ('java.lang.Runnable', 'run'),
        ('java.util.concurrent.Executor', 'execute'),
        ('java.util.concurrent.Callable', 'call'),
        ('java.lang.System', 'console'),
        ('java.lang.System', 'load'),
        ('java.lang.System', 'loadLibrary'),
        ('java.lang.System', 'apLibraryName'),
        ('java.lang.System', 'runFinalization'),
        ('java.lang.System', 'setErr'),
        ('java.lang.System', 'setIn'),
        ('java.lang.System', 'setOut'),
        ('java.lang.System', 'setProperties'),
        ('java.lang.System', 'setProperty'),
        ('java.lang.System', 'setSecurityManager'),
        ('java.lang.ProcessBuilder', 'directory'),
        ('java.lang.ProcessBuilder', 'inheritIO'),
        ('java.lang.ProcessBuilder', 'command'),
        ('java.lang.ProcessBuilder', 'edirectError'),
        ('java.lang.ProcessBuilder', 'redirectErrorStream'),
        ('java.lang.ProcessBuilder', 'redirectInput'),
        ('java.lang.ProcessBuilder', 'redirectOutput'),
        ('java.lang.ProcessBuilder', 'start')
    ]
}


class Analysis(analysis.AnalysisInterface):
    """This Analysis aims to analyse and generate html report content table
    to show all occurence of possible sink functions / methods existed in the
    target project and if those functions / methods are statically reached or
    dynamically covered by any of the fuzzers. If not, it also provides the
    closet callable entry points to those sink functions / methods for fuzzer
    developers to improve their fuzzers to statically reached and dynamically
    covered those sensitive sink fnctions / method in aid to discover possible
    code / command injection through though fuzzing on sink functions / methods..
    """

    def __init__(self) -> None:
        pass

    @staticmethod
    def get_name():
        return "SinkCoverageAnalyser"

    def analysis_func(
        self,
        toc_list: List[Tuple[str, str, int]],
        tables: List[str],
        proj_profile: project_profile.MergedProjectProfile,
        profiles: List[fuzzer_profile.FuzzerProfile],
        basefolder: str,
        coverage_url: str,
        conclusions: List[html_helpers.HTMLConclusion]
    ) -> str:
        """
        Show all used sensitive sink functions / methods in the project and display
        if any fuzzers statically or dynamically reached them. If not, display closest
        entry point to reach them.
        1) Loop through the all function list of the project and see if any of the sink
           functions exists.
        2) Shows if each of those third party function call location is statically
           reachable
        3) Analyse and show closet entry point suggestions for fuzzers developer to
           statically reached those functions / methods
        4) Analyse the fuzzer report to determine if each of those statically reachable
           sink functions / methods has been dynamically coveed by any of the fuzzers
        5) Provide additional entry point to increase the chance of dynamically covering
           those sink functions / methods.
        """
        logger.info(f" - Running analysis {Analysis.get_name()}")

        html_string = ""
        html_string += html_helpers.html_add_header_with_link(
            "Sink funcions / methods analysis", 2, toc_list)

        sink_list = self.retrieve_sinks_functions(
            proj_profile.all_functions,
            profiles[0].target_lang
        )

        # Create sinks analysis section
        html_string += self.get_sink_func_section(
            sink_list,
            toc_list,
            tables,
            coverage_url,
            profiles[0].target_lang
        )

        logger.info(f" - Completed analysis {Analysis.get_name()}")
        html_string += "</div>"  # .collapsible
        return html_string

    def retrieve_sinks_functions(
       self,
       function_list: Dict[str, function_profile.FunctionProfile],
       target_lang: str = 'c-cpp'
   ) -> List[function_profile.FunctionProfile]:
        return []

    def get_sink_func_section(
        self,
        sink_function: List[function_profile.FunctionProfile],
        toc_list: List[Tuple[str, str, int]],
        tables: List[str],
        coverage_url: str,
        target_lang: str = 'c-cpp'
    ) -> str:
        return ""

