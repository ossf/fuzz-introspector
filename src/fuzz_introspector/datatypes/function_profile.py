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
"""Function profile"""

import logging

from typing import (
    Any,
    Dict,
    List,
)

from fuzz_introspector.datatypes import branch_profile
from fuzz_introspector import utils

logger = logging.getLogger(name=__name__)
logger.setLevel(logging.INFO)


class FunctionProfile:
    """
    Class for storing information about a given Function
    """
    def __init__(self, elem: Dict[Any, Any]) -> None:
        self.function_name = utils.demangle_cpp_func(elem['functionName'])
        self.function_source_file = elem['functionSourceFile']
        self.linkage_type = elem['linkageType']
        self.function_linenumber = elem['functionLinenumber']
        self.return_type = elem['returnType']
        self.arg_count = elem['argCount']
        self.arg_types = elem['argTypes']
        self.arg_names = elem['argNames']
        self.bb_count = elem['BBCount']
        self.i_count = elem['ICount']
        self.edge_count = elem['EdgeCount']
        self.cyclomatic_complexity = elem['CyclomaticComplexity']
        self.functions_reached = utils.load_func_names(elem['functionsReached'])
        self.function_uses = elem['functionUses']
        self.function_depth = elem['functionDepth']
        self.constants_touched = elem['constantsTouched']
        self.branch_profiles = self.load_func_branch_profiles(elem['BranchProfiles'])

        # Saving callsites for this function
        try:
            self.callsite = self.load_func_callsites(elem['Callsites'])
        except Exception:
            self.callsite = dict()

        # These are set later.
        self.hitcount: int = 0
        self.reached_by_fuzzers: List[str] = []
        self.incoming_references: List[str] = []
        self.new_unreached_complexity: int = 0
        self.total_cyclomatic_complexity: int = 0

    def load_func_branch_profiles(
        self,
        yaml_branch_profiles: Any
    ) -> Dict[str, branch_profile.BranchProfile]:
        bp_loaded = {}
        for entry in yaml_branch_profiles:
            new_branch = branch_profile.BranchProfile()
            new_branch.assign_from_yaml_elem(entry)
            bp_loaded[new_branch.branch_pos] = new_branch

        return bp_loaded

    def load_func_callsites(
        self,
        yaml_callsites: Any
    ) -> Dict[str, List[str]]:
        cs_loaded: Dict[str, List[str]] = {}
        for callsite in yaml_callsites:
            if callsite['Dst'] not in cs_loaded.keys():
                callsite_list = []
            else:
                callsite_list = cs_loaded[callsite['Dst']]

            callsite_src = callsite['Src'].split(',')[0].replace(
                ':',
                '#%s:' % self.function_name
            )
            callsite_list.append(callsite_src)
            cs_loaded.update({callsite['Dst']: callsite_list})

        return cs_loaded
