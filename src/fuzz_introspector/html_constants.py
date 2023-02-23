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
"""Module for holding HTML-specific constants."""

from fuzz_introspector import constants

INFO_ALL_FUNCTION_OVERVIEW_TEXT = f"""<p>
    The following table shows data about each function in the project.
    The functions included in this table correspond to all functions
    that exist in the executables of the fuzzers. As such, there may
    be functions that are from third-party libraries.
</p>
<p>
    For further technical details on the meaning of columns in the
	below table, please see the
	<a href="{constants.GIT_BRANCH_URL}/doc/Glossary.md#project-functions-overview">Glossary</a>.
</p>"""

INFO_SUM_OF_COVERED_FUNCS_EQ_REACHABLE_FUNCS = """<div style="font-size: 0.85rem; color: #adadad; margin-bottom: 40px">
    <b>NB:</b> The sum of <i>covered functions</i> and <i>functions
    that are reachable but not covered</i> need not be equal to <i>Reachable
    functions</i>. This is because the reachability analysis is an
    approximation and thus at runtime some functions may be covered
    that are not included in the reachability analysis. This is a
    limitation of our static analysis capabilities.
</div>
"""

INFO_CALLTREE_DESCRIPTION = f"""The calltree shows the
control flow of the fuzzer. This is overlaid with coverage information
to display how much of the potential code a fuzzer can reach is in fact
covered at runtime.
In the following there is a link to a detailed calltree visualisation
as well as a bitmap showing a high-level view of the calltree. For
further information about these topics please see the glossary for
<a href="{constants.GIT_BRANCH_URL}/doc/Glossary.md#full-calltree">
full calltree</a> and
<a href="{constants.GIT_BRANCH_URL}/doc/Glossary.md#call-tree-overview">
calltree overview</a>"""

# Calltree button, must be formatted with calltree file name.
INFO_CALLTREE_LINK_BUTTON = """<p class='no-top-margin'>
    <div class="yellow-button-wrapper"
         style="position: relative; margin: 30px 0 5px 0; max-width: 200px">
        <a href="{0}">
            <div class="yellow-button">
            Full calltree
            </div>
        </a>
    </div>
</p>"""

WARNING_TOTAL_FUNC_OVER_REACHABLE_FUNC = """<div class="warning-box-wrapper">
	<span class="warning-box red-warning">
		<b>Warning:</b> The number of covered functions are larger than the 
		number of reachable functions. This means that there are more functions covered at
		runtime than are extracted using static analysis. This is likely a result
		of the static analysis component failing to extract the right
		call graph or the coverage runtime being compiled with sanitizers in code that
		the static analysis has not analysed. This can happen if lto/gold is not
		used in all places that coverage instrumentation is used.
	</span>
</div>"""
