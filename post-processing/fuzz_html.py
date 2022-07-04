# Copyright 2021 Fuzz Introspector Authors
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

"""Module for creating HTML reports"""
import os
import logging
import shutil
import json
import typing

from typing import (
    Any,
    Dict,
    List,
    Optional,
    Tuple,
)

import fuzz_analysis
import fuzz_data_loader
import fuzz_utils
import fuzz_cfg_load
import fuzz_constants
import fuzz_html_helpers

# For pretty printing the html code:
from bs4 import BeautifulSoup as bs

import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle

import random
import string

logger = logging.getLogger(name=__name__)


def create_horisontal_calltree_image(image_name: str,
                                     profile: fuzz_data_loader.FuzzerProfile) -> None:
    """
    Creates a horisontal image of the calltree. The height is fixed and
    each element on the x-axis shows a node in the calltree in the form
    of a rectangle. The rectangle is red if not visited and green if visited.
    """

    logger.info(f"Creating image {image_name}")

    if profile.function_call_depths is None:
        return
    # Extract color sequence
    color_list: List[str] = []
    for node in fuzz_cfg_load.extract_all_callsites(profile.function_call_depths):
        color_list.append(node.cov_color)
    logger.info(f"- extracted the callsites ({len(color_list)} nodes)")

    # Show one read rectangle if the list is empty. An alternative is
    # to not include the image at all.
    if len(color_list) == 0:
        color_list = ['red']
    plot_size = len(color_list)
    multiplier = plot_size / len(color_list)

    fig, ax = plt.subplots()
    ax.clear()
    fig.set_size_inches(15, 2.5)
    ax.plot()

    # Create our rectangles
    curr_start_x = 0.0
    curr_size = 1.0
    curr_color = color_list[0]
    height = 1.0

    for i in range(1, len(color_list)):
        if curr_color == color_list[i]:
            curr_size += 1.0
        else:
            final_start_x = curr_start_x * multiplier
            final_size = curr_size * multiplier
            ax.add_patch(
                Rectangle(
                    (final_start_x, 0.0),
                    final_size,
                    height,
                    color=curr_color
                )
            )

            # Start next color area
            curr_start_x += curr_size
            curr_color = color_list[i]
            curr_size = 1.0
    logger.info("- iterated over color list")

    # Plot the last case
    final_start_x = curr_start_x * multiplier
    final_size = curr_size * multiplier
    ax.add_patch(Rectangle((final_start_x, 0.0), final_size, height, color=curr_color))
    ax.set_yticklabels([])
    ax.set_yticks([])
    xlabel = ax.set_xlabel("Callsite index")

    # Save the image
    logger.info("- saving image")
    plt.title(image_name.replace(".png", "").replace("_colormap", ""))
    fig.tight_layout()
    fig.savefig(image_name, bbox_extra_artists=[xlabel])
    logger.info("- image saved")


def create_overview_table(tables: List[str],
                          profiles: List[fuzz_data_loader.FuzzerProfile]) -> str:
    """Table with an overview of all the fuzzers"""
    html_string = fuzz_html_helpers.html_create_table_head(tables[-1], [
        ("Fuzzer",
         "Fuzzer key. Usually fuzzer executable file"),
        ("Fuzzer filename",
         "Fuzzer source code file"),
        ("Functions Reached",
         "Number of functions this fuzzer reaches. This data is based on static analysis."),
        ("Functions unreached",
         "Number of functions unreached by this fuzzer. This data is based on static analysis."),
        ("Fuzzer depth",
         "Function call depth of this fuzer."),
        ("Files reached",
         "Source code files reached by the fuzzer."),
        ("Basic blocks reached",
         "The total number of basic blocks of all functions reached by the fuzzer."),
        ("Cyclomatic complexity",
         "The accummulated cyclomatic complexity of all functions reached by the fuzzer."),
        ("Details",
         "")
    ])
    for profile in profiles:  # create a row for each fuzzer.
        fuzzer_filename = profile.fuzzer_source_file
        max_depth = 0
        for cs in fuzz_cfg_load.extract_all_callsites(profile.function_call_depths):
            if cs.depth > max_depth:
                max_depth = cs.depth

        html_string += fuzz_html_helpers.html_table_add_row([
            profile.get_key(),
            fuzzer_filename,
            len(profile.functions_reached_by_fuzzer),
            len(profile.functions_unreached_by_fuzzer),
            max_depth,
            len(profile.file_targets),
            profile.total_basic_blocks,
            profile.total_cyclomatic_complexity,
            fuzzer_filename.replace(" ", "").split("/")[-1]])
    html_string += ("\n</tbody></table>")
    return html_string


def create_all_function_table(
        tables: List[str],
        project_profile: fuzz_data_loader.MergedProjectProfile,
        coverage_url: str,
        basefolder: str,
        table_id: Optional[str] = None
) -> Tuple[str, List[typing.Dict[str, Any]]]:
    """Table for all functions in the project. Contains many details about each
        function"""
    random_suffix = '_' + ''.join(
        random.choices(string.ascii_lowercase + string.ascii_uppercase, k=7))
    if table_id is None:
        table_id = tables[-1]

    table_columns = [
        ("Func name",
         ""),
        ("Functions filename",
         "Source code file where function is defined."),
        ("Args",
         "Types of arguments to this function."),
        ("Function call depth",
         "Function call depth based on static analysis."),
        ("Reached by Fuzzers",
         "The specific fuzzers that reach this function. Based on static analysis."),
        ("Fuzzers runtime hit",
         "Indicates whether the function is hit at runtime by the given corpus. "
         "Based on dynamic analysis."),
        ("Func lines hit %",
         "Indicates the percentage of the function that is covered at runtime. "
         "This is based on dynamic analysis."),
        ("I Count",
         "Instruction count. The number of LLVM instructions in the function."),
        ("BB Count",
         "Basic block count. The number of basic blocks in the function."),
        ("Cyclomatic complexity",
         "The cyclomatic complexity of the function."),
        ("Functions reached",
         "The number of functions reached, based on static analysis."),
        ("Reached by functions",
         "The number of functions that reaches this function, based on static analysis."),
        ("Accumulated cyclomatic complexity",
         "Accummulated cyclomatic complexity of all functions reachable by this function. "
         "Based on static analysis."),
        ("Undiscovered complexity", "")
    ]
    html_string = fuzz_html_helpers.html_create_table_head(
        table_id,
        table_columns,
        sort_by_column=len(table_columns) - 1,
        sort_order="desc"
    )

    # an array in development to replace html generation in python.
    # this will be stored as a json object and will be used to populate
    # the table in the frontend
    table_rows = []

    for fd_k, fd in project_profile.all_functions.items():
        demangled_func_name = fuzz_utils.demangle_cpp_func(fd.function_name)
        try:
            func_total_lines, hit_lines = project_profile.runtime_coverage.get_hit_summary(
                demangled_func_name
            )
            if hit_lines is None or func_total_lines is None:
                hit_percentage = 0.0
            else:
                hit_percentage = (hit_lines / func_total_lines) * 100.0
        except Exception:
            hit_percentage = 0.0

        func_cov_url = "%s%s.html#L%d" % (
            coverage_url,
            fd.function_source_file,
            fd.function_linenumber
        )

        if project_profile.runtime_coverage.is_func_hit(fd.function_name):
            func_hit_at_runtime_row = "yes"
        else:
            func_hit_at_runtime_row = "no"

        func_name_row = f"""<a href='{ func_cov_url }'><code class='language-clike'>
            { demangled_func_name }
            </code></a>"""

        collapsible_id = demangled_func_name + random_suffix

        if fd.hitcount > 0:
            reached_by_fuzzers_row = create_collapsible_element(
                str(fd.hitcount),
                str(fd.reached_by_fuzzers),
                collapsible_id
            )
        else:
            reached_by_fuzzers_row = "0"

        if fd.arg_count > 0:
            args_row = create_collapsible_element(
                str(fd.arg_count),
                str(fd.arg_types),
                collapsible_id + "2"
            )
        else:
            args_row = "0"

        table_rows.append({
            "Func name": func_name_row,
            "func_url": func_cov_url,
            "Functions filename": fd.function_source_file,
            "Args": args_row,
            "Function call depth": fd.function_depth,
            "Reached by Fuzzers": reached_by_fuzzers_row,
            "collapsible_id": collapsible_id,
            "Fuzzers runtime hit": func_hit_at_runtime_row,
            "Func lines hit %": "%.5s" % (str(hit_percentage)) + "%",
            "I Count": fd.i_count,
            "BB Count": fd.bb_count,
            "Cyclomatic complexity": fd.cyclomatic_complexity,
            "Functions reached": len(fd.functions_reached),
            "Reached by functions": len(fd.incoming_references),
            "Accumulated cyclomatic complexity": fd.total_cyclomatic_complexity,
            "Undiscovered complexity": fd.new_unreached_complexity
        })
    html_string += ("</table>\n")
    return html_string, table_rows


def create_collapsible_element(
    non_collapsed: str,
    collapsed: str,
    collapsible_id: str
) -> str:
    return f"""{ non_collapsed } : <div
    class='wrap-collabsible'>
        <input id='{collapsible_id}'
               class='toggle'
               type='checkbox'>
            <label
                for='{collapsible_id}'
                class='lbl-toggle'>
                    View List
            </label>
        <div class='collapsible-content'>
            <div class='content-inner'>
                <p>
                    {collapsed}
                </p>
            </div>
        </div>
    </div>"""


def create_percentage_graph(title: str, percentage: str, numbers: str) -> str:
    return f"""<div style="flex:1; margin-right: 20px"class="report-box mt-0">
            <div style="font-weight: 600; text-align: center;">
                {title}
            </div>
            <div class="flex-wrapper">
              <div class="single-chart">
                <svg viewBox="0 0 36 36" class="circular-chart green">
                  <path class="circle-bg"
                    d="M18 2.0845
                      a 15.9155 15.9155 0 0 1 0 31.831
                      a 15.9155 15.9155 0 0 1 0 -31.831"
                  />
                  <path class="circle"
                    stroke-dasharray="{percentage}, 100"
                    d="M18 2.0845
                      a 15.9155 15.9155 0 0 1 0 31.831
                      a 15.9155 15.9155 0 0 1 0 -31.831"
                  />
                  <text x="18" y="20.35" class="percentage">{percentage}%</text>
                </svg>
              </div>
            </div>
            <div style="font-size: .9rem; color: #b5b5b5; text-align: center">
              {numbers}
            </div>
        </div>"""


def create_covered_func_box(covered_funcs: str) -> str:
    return f"""<div
    style="flex:1; flex-direction: column; display: flex;"
    class="report-box">

    <div style="font-weight: 600; text-align: center; flex: 1">
        Functions covered at runtime
    </div>
    <div style="text-align: center; font-size: 3rem; font-weight: 450; flex: 3; padding-top: 20%">
        {covered_funcs}
    </div>
</div>"""


def create_boxed_top_summary_info(
    tables: List[str],
    project_profile: fuzz_data_loader.MergedProjectProfile,
    conclusions: List[Tuple[int, str]],
    extract_conclusion: bool,
    display_coverage: bool = False
) -> str:
    html_string = ""
    # Get complexity and function counts
    (total_functions,
     reached_func_count,
     unreached_func_count,
     reached_percentage,
     unreached_percentage) = project_profile.get_function_summaries()
    (total_complexity,
     complexity_reached,
     complexity_unreached,
     reached_complexity_percentage,
     unreached_complexity_percentage) = project_profile.get_complexity_summaries()

    graph1_title = "Functions statically reachable by fuzzers"
    graph1_percentage = str(round(reached_percentage, 2))
    graph1_numbers = f"{reached_func_count}/{total_functions}"
    html_string += create_percentage_graph(graph1_title, graph1_percentage, graph1_numbers)

    graph2_title = "Cyclomatic complexity statically reachable by fuzzers"
    graph2_percentage = str(round(reached_complexity_percentage, 2))
    graph2_numbers = f"{complexity_reached}/{int(total_complexity)}"
    html_string += create_percentage_graph(graph2_title, graph2_percentage, graph2_numbers)
    if display_coverage:
        logger.info("Displaying coverage in summary")
        covered_funcs = project_profile.get_all_runtime_covered_functions()
        html_string += create_covered_func_box(str(len(covered_funcs)))

    # Add conclusion
    if extract_conclusion:
        create_conclusions(conclusions, reached_percentage, reached_complexity_percentage)
    return html_string


def create_conclusions(
    conclusions: List[Tuple[int, str]],
    reached_percentage: float,
    reached_complexity_percentage: float
) -> None:
    # Functions reachability
    sentence = f"""Fuzzers reach { "%.5s%%"%(str(reached_percentage)) } of all functions. """
    if reached_percentage > 90.0:
        warning = 10
        sentence += "This is great."
    elif reached_percentage > 75.0:
        warning = 8
        sentence += "This is good"
    elif reached_percentage > 50.0:
        warning = 6
        sentence += "This is good, but there's room for improvement."
    elif reached_percentage > 25.0:
        warning = 4
        sentence += "Improvements should be made"
    else:
        warning = 2
        sentence += "Improvements need to be made"
    conclusions.append((warning, sentence))

    # Complexity reachability
    percentage_str = "%.5s%%" % str(reached_complexity_percentage)
    sentence = f"Fuzzers reach { percentage_str } of cyclomatic complexity. "
    if reached_complexity_percentage > 90.0:
        warning = 10
        sentence += "This is great."
    elif reached_complexity_percentage > 70.0:
        warning = 8
        sentence += "This is pretty nice."
    elif reached_complexity_percentage > 50.0:
        warning = 6
        sentence += "This is okay."
    else:
        warning = 2
        sentence += "Improvements could be made"
    conclusions.append((warning, sentence))


def create_top_summary_info(
        tables: List[str],
        project_profile: fuzz_data_loader.MergedProjectProfile,
        conclusions: List[Tuple[int, str]],
        extract_conclusion: bool,
        display_coverage: bool = False) -> str:
    html_string = ""

    # Get complexity and function counts
    (total_functions,
     reached_func_count,
     unreached_func_count,
     reached_percentage,
     unreached_percentage) = project_profile.get_function_summaries()
    (total_complexity,
     complexity_reached,
     complexity_unreached,
     reached_complexity_percentage,
     unreached_complexity_percentage) = project_profile.get_complexity_summaries()

    # Display reachability information
    html_string += "<div style=\"display: flex; max-width: 50%\">"
    graph1_title = "Functions statically reachable by fuzzers"
    graph1_percentage = str(round(reached_percentage, 2))
    graph1_numbers = f"{reached_func_count}/{total_functions}"
    html_string += create_percentage_graph(graph1_title, graph1_percentage, graph1_numbers)

    graph2_title = "Cyclomatic complexity statically reachable by fuzzers"
    graph2_percentage = str(round(reached_complexity_percentage, 2))
    graph2_numbers = f"{complexity_reached} / {int(total_complexity)}"
    html_string += create_percentage_graph(graph2_title, graph2_percentage, graph2_numbers)
    html_string += "</div>"
    if display_coverage:
        logger.info("Displaying coverage in summary")
        covered_funcs = project_profile.get_all_runtime_covered_functions()
        html_string += f"Functions covered at runtime: { len(covered_funcs) }"
        html_string += "<br>"
    else:
        logger.info("Not displaying coverage in summary")

    # Add conclusion
    if extract_conclusion:
        create_conclusions(conclusions, reached_percentage, reached_complexity_percentage)

    return html_string


def create_fuzzer_detailed_section(
    profile: fuzz_data_loader.FuzzerProfile,
    toc_list: List[Tuple[str, str, int]],
    tables: List[str],
    curr_tt_profile: int,
    conclusions: List[Tuple[int, str]],
    extract_conclusion: bool,
    fuzzer_table_data: Dict[str, Any]
) -> str:
    html_string = ""
    html_string += fuzz_html_helpers.html_add_header_with_link(
        f"Fuzzer: {profile.get_key()}",
        2,
        toc_list
    )

    # Calltree fixed-width image
    html_string += fuzz_html_helpers.html_add_header_with_link(
        "Call tree", 3, toc_list, link=f"call_tree_{curr_tt_profile}")
    html_string += (
        f"<p class='no-top-margin'>\n"
        f"The following is the call tree with color coding for which "
        f"functions are hit/not hit. This info is based on the coverage "
        f"achieved of all fuzzers together and not just this specific "
        f"fuzzer."
        f"</p>"
        f"<p><ul>"
        f"<li>Red: no hits</li>"
        f"<li>Yellow: few hits</li>"
        f"<li>Green: many hits</li>"
        f"</ul></p>"
        f"<p>"
        f"For further technical details on the call tree overview"
        f", please see the <a href=\"{fuzz_constants.GIT_BRANCH_URL}/doc/"
        f"Glossary.md#call-tree-overview\">Glossary</a>."
        f"</p>"
    )

    colormap_file_prefix = profile.get_key()
    if "/" in colormap_file_prefix:
        colormap_file_prefix = colormap_file_prefix.replace("/", "_")
    image_name = f"{colormap_file_prefix}_colormap.png"

    create_horisontal_calltree_image(image_name, profile)
    html_string += f"<img class=\"colormap\" src=\"{image_name}\">"

    # Full calltree
    html_string += fuzz_html_helpers.html_add_header_with_link(
        "Full call tree",
        3,
        [],
        link=f"full_calltree_{curr_tt_profile}"
    )

    from analyses import fuzz_calltree_analysis
    calltree_analysis = fuzz_calltree_analysis.FuzzCalltreeAnalysis()
    calltree_file_name = calltree_analysis.create_calltree(profile)

    html_string += f"""<p class='no-top-margin'>The following link provides a visualisation
 of the full call tree overlaid with coverage information:
 <a href="{ calltree_file_name }">full call tree</a></p>"""
    html_string += f"<p>For further technical details on how the call tree is generated, please " \
                   f"see the <a href=\"{fuzz_constants.GIT_BRANCH_URL}/doc/Glossary.md#full" \
                   f"-calltree\">Glossary</a>.</p>"

    # Fuzz blocker table
    html_fuzz_blocker_table = calltree_analysis.create_fuzz_blocker_table(
        profile,
        tables,
        calltree_file_name
    )
    if html_fuzz_blocker_table is not None:
        html_string += fuzz_html_helpers.html_add_header_with_link(
            "Fuzz blockers",
            3,
            toc_list,
            link=f"fuzz_blocker{curr_tt_profile}"
        )
        html_string += html_fuzz_blocker_table

    profile.write_stats_to_summary_file()

    # Table with all functions hit by this fuzzer
    html_string += fuzz_html_helpers.html_add_header_with_link(
        "Runtime coverage analysis",
        3,
        toc_list,
        link=f"functions_cov_hit_{curr_tt_profile}"
    )
    table_name = f"myTable{len(tables)}"

    # Add this table name to fuzzer_table_data
    fuzzer_table_data[table_name] = []

    tables.append(table_name)
    func_hit_table_string = ""
    func_hit_table_string += fuzz_html_helpers.html_create_table_head(
        tables[-1],
        [
            ("Function name", ""),
            ("source code lines", ""),
            ("source lines hit", ""),
            ("percentage hit", "")
        ],
        1,
        "desc"
    )

    total_hit_functions = 0
    if profile.coverage is not None:
        for funcname in profile.coverage.covmap:
            (total_func_lines,
             hit_lines,
             hit_percentage) = profile.get_cov_metrics(funcname)

            if hit_percentage is not None:
                total_hit_functions += 1
                fuzzer_table_data[table_name].append({
                    "Function name": funcname,
                    "source code lines": total_func_lines,
                    "source lines hit": hit_lines,
                    "percentage hit": "%.5s" % (str(hit_percentage)) + "%"
                })
                '''func_hit_table_string += html_table_add_row([
                    funcname,
                    total_func_lines,
                    hit_lines,
                    "%.5s" % (str(hit_percentage)) + "%"])'''
            else:
                logger.error("Could not write coverage line for function %s" % funcname)
    func_hit_table_string += "</table>"

    # Get how many functions are covered relative to reachability
    uncovered_reachable_funcs = len(profile.get_cov_uncovered_reachable_funcs())
    reachable_funcs = len(profile.functions_reached_by_fuzzer)
    reached_funcs = reachable_funcs - uncovered_reachable_funcs
    try:
        cov_reach_proportion = (float(reached_funcs) / float(reachable_funcs)) * 100.0
    except Exception:
        logger.info("reachable funcs is 0")
        cov_reach_proportion = 0.0
    str_percentage = "%.5s%%" % str(cov_reach_proportion)
    fuzz_utils.write_to_summary_file(
        profile.get_key(),
        "coverage-blocker-stats",
        {
            "reachable-funcs": reachable_funcs,
            "reached-funcs": reached_funcs,
            "cov-reach-proportion": cov_reach_proportion,
        }
    )
    if extract_conclusion:
        if cov_reach_proportion < 30.0:
            conclusions.append((
                2,
                (f"Fuzzer { profile.get_key() } is blocked: runtime coverage only "
                 f"covers { str_percentage } of its reachable functions.")
            ))

    html_string += "<div style=\"display: flex; margin-bottom: 10px;\">"
    html_string += get_simple_box("Covered functions", str(total_hit_functions))
    html_string += get_simple_box(
        "Functions that are reachable but not covered",
        str(uncovered_reachable_funcs)
    )
    html_string += get_simple_box("Reachable functions", str(reachable_funcs))
    html_string += get_simple_box(
        "Percentage of reachable functions covered",
        "%s%%" % str(round(cov_reach_proportion, 2))
    )
    html_string += "</div>"
    html_string += "<div style=\"font-size: 0.85rem; color: #adadad; margin-bottom: 40px\">"
    html_string += "<b>NB:</b> The sum of <i>covered functions</i> and <i>functions " \
                   "that are reachable but not covered</i> need not be equal to <i>Reachable " \
                   "functions</i>. This is because the reachability analysis is an "  \
                   "approximation and thus at runtime some functions may be covered " \
                   "that are not included in the reachability analysis. This is a "   \
                   "limitation of our static analysis capabilities."
    html_string += "</div>"

    if total_hit_functions > reachable_funcs:
        html_string += (
            "<div class=\"high-level-conclusions-wrapper\">"
            "<span class=\"high-level-conclusion red-conclusion\">"
            "<b>Warning:</b> The number of covered functions are larger than the "
            "number of reachable functions. This means that there are more functions covered at "
            "runtime than are extracted using static analysis. This is likely a result "
            "of the static analysis component failing to extract the right "
            "call graph or the coverage runtime being compiled with sanitizers in code that "
            "the static analysis has not analysed. This can happen if lto/gold is not "
            "used in all places that coverage instrumentation is used."
            "</span>"
            "</div>"
        )

    html_string += func_hit_table_string

    # Table showing which files this fuzzer hits.
    html_string += fuzz_html_helpers.html_add_header_with_link(
        "Files reached", 3, toc_list, link=f"files_hit_{curr_tt_profile}")
    tables.append(f"myTable{len(tables)}")
    html_string += fuzz_html_helpers.html_create_table_head(
        tables[-1],
        [
            ("filename", ""),
            ("functions hit", "")
        ])
    for k in profile.file_targets:
        html_string += fuzz_html_helpers.html_table_add_row(
            [k, len(profile.file_targets[k])]
        )
    html_string += "</table>\n"
    return html_string


def get_simple_box(title: str, value: str) -> str:
    return f"""<div class="report-box" style="flex: 1; display: flex; flex-direction: column;">
        <div style="font-size: 0.9rem;">
          {title}
        </div>
        <div style="font-size: 1.2rem; font-weight: 550;">
          {value}
        </div>
      </div>"""


def extract_highlevel_guidance(conclusions: List[Tuple[int, str]]) -> str:
    """
    Creates colorful boxes for the conlusions made throughout the analysis
    """
    logger.info("Extracting high level guidance")
    html_string = ""
    html_string += "<div class=\"high-level-conclusions-wrapper\">"

    # Sort conclusions to show highest level (positive conclusion) first
    conclusions = list(reversed(sorted(conclusions)))
    for lvl, sentence in conclusions:
        if lvl < 5:
            conclusion_color = "red"
        elif lvl < 8:
            conclusion_color = "yellow"
        else:
            conclusion_color = "green"
        html_string += f"""<div class="line-wrapper">
    <div class="high-level-conclusion { conclusion_color }-conclusion collapsed">
    { sentence }
        <div class="high-level-extended" style="background:transparent; overflow:hidden">
            Description
        </div>
    </div>
</div>"""
    html_string += "</div>"
    return html_string


def create_html_report(
    profiles: List[fuzz_data_loader.FuzzerProfile],
    project_profile: fuzz_data_loader.MergedProjectProfile,
    analyses_to_run: List[str],
    coverage_url: str,
    basefolder: str,
    report_name: str
) -> None:
    """
    Logs a complete report. This is the current main place for looking at
    data produced by fuzz introspector.
    """
    tables: List[str] = list()
    toc_list: List[Tuple[str, str, int]] = list()
    conclusions: List[Tuple[int, str]] = []

    logger.info(" - Creating HTML report")

    # Create html header, which will be used to assemble the doc at the
    # end of this function.
    html_header = fuzz_html_helpers.html_get_header()

    # Start creation of core html
    html_body_start = '<div class="content-section">'
    html_overview = "<div class=\"report-box\">"
    html_overview += fuzz_html_helpers.html_add_header_with_link(
        f"Project overview: {report_name}",
        1,
        toc_list,
        link="Project-overview"
    )
    project_profile.write_stats_to_summary_file()
    html_overview += "<div class=\"collapsible\">"

    # Project overview
    # html_overview += fuzz_html_helpers.html_add_header_with_link(
    #   "Project information", 2, toc_list)

    #############################################
    # Section with high level suggestions
    #############################################
    html_report_top = fuzz_html_helpers.html_add_header_with_link(
        "High level conclusions",
        2,
        toc_list
    )

    #############################################
    # Reachability overview
    #############################################
    logger.info(" - Creating reachability overview table")
    html_report_core = fuzz_html_helpers.html_add_header_with_link(
        "Reachability and coverage overview",
        2,
        toc_list
    )
    tables.append(f"myTable{len(tables)}")
    html_report_core += "<div style=\"display: flex; max-width: 800px\">"
    html_report_core += create_boxed_top_summary_info(
        tables,
        project_profile,
        conclusions,
        True,
        display_coverage=True
    )
    # Boxed summary
    html_report_core += "</div>"

    # .collapsible
    html_report_core += "</div>"

    # report-box
    html_report_core += "</div>"

    #############################################
    # Table with overview of all fuzzers.
    #############################################
    logger.info(" - Creating table with overview of all fuzzers")
    html_report_core += "<div class=\"report-box\">"
    html_report_core += fuzz_html_helpers.html_add_header_with_link(
        "Fuzzers overview",
        1,
        toc_list
    )
    html_report_core += "<div class=\"collapsible\">"
    tables.append(f"myTable{len(tables)}")
    html_report_core += create_overview_table(tables, profiles)

    # report-box
    html_report_core += "</div>"  # .collapsible
    html_report_core += "</div>"

    #############################################
    # Table with details about all functions in the target project.
    #############################################
    logger.info(" - Creating table with information about all functions in target")
    html_report_core += "<div class=\"report-box\">"
    html_report_core += fuzz_html_helpers.html_add_header_with_link(
        "Project functions overview", 1, toc_list)
    html_report_core += "<div class=\"collapsible\">"
    html_report_core += "<p> The following table shows data about each function in the project. " \
                        "The functions included in this table correspond to all functions " \
                        "that exist in the executables of the fuzzers. As such, there may  " \
                        "be functions that are from third-party libraries.</p>"
    html_report_core += f"<p>For further technical details on the meaning of columns in the " \
                        f"below table, please see the " \
                        f"<a href=\"{fuzz_constants.GIT_BRANCH_URL}/doc/Glossary.md#project-"\
                        f"functions-overview\">Glossary</a>.</p>"

    table_id = "fuzzers_overview_table"
    tables.append(table_id)
    all_function_table, all_functions_json = create_all_function_table(
        tables, project_profile, coverage_url, basefolder, table_id)
    html_report_core += all_function_table
    html_report_core += "</div>"  # .collapsible
    html_report_core += "</div>"  # report box

    #############################################
    # Section with details about each fuzzer, including calltree.
    #############################################
    logger.info(" - Creating section with details about each fuzzer")
    fuzzer_table_data: Dict[str, Any] = dict()
    html_report_core += "<div class=\"report-box\">"
    html_report_core += fuzz_html_helpers.html_add_header_with_link("Fuzzer details", 1, toc_list)
    html_report_core += "<div class=\"collapsible\">"
    for profile_idx in range(len(profiles)):
        html_report_core += create_fuzzer_detailed_section(
            profiles[profile_idx],
            toc_list,
            tables,
            profile_idx,
            conclusions,
            True,
            fuzzer_table_data
        )
    html_report_core += "</div>"  # .collapsible
    html_report_core += "</div>"  # report box

    #############################################
    # Handle optional analyses
    #############################################
    logger.info(" - Handling optional analyses")
    html_report_core += "<div class=\"report-box\">"
    html_report_core += fuzz_html_helpers.html_add_header_with_link(
        "Analyses and suggestions",
        1,
        toc_list
    )
    html_report_core += "<div class=\"collapsible\">"

    analysis_array = fuzz_analysis.get_all_analyses()
    for analysis in analysis_array:
        if analysis.name in analyses_to_run:
            html_report_core += analysis.analysis_func(
                toc_list,
                tables,
                project_profile,
                profiles,
                basefolder,
                coverage_url,
                conclusions)
    html_report_core += "</div>"  # .collapsible
    html_report_core += "</div>"  # report box

    #############################################
    # End of optional analyses
    #############################################

    #############################################
    # Create top level conclusions
    #############################################
    html_report_top += extract_highlevel_guidance(conclusions)

    # Wrap up the HTML generation
    # Close the content div and content_wrapper
    html_body_end = "</div>\n</div>\n"

    # .js files to add to report
    js_files = ["prism.js", "clike.js", "custom.js", "all_functions.js",
                "analysis_1.js", "fuzzer_table_data.js",
                "https://cdn.datatables.net/buttons/2.2.2/js/dataTables.buttons.min.js",
                "https://cdn.datatables.net/buttons/2.2.2/js/buttons.colVis.min.js"]
    for js_file in js_files:
        html_body_end += f"<script src=\"{js_file}\"></script>"

    ###########################
    # Footer
    ###########################
    html_footer = "<script>\n"

    # Create array of all table ids
    html_footer += "var tableIds = ["
    counter = 0
    for tablename in tables:
        html_footer += f"'{tablename}'"
        if counter != len(tables) - 1:
            html_footer += ", "
        else:
            html_footer += "];\n"
        counter += 1

    # Closing tags
    html_footer += ("</script>\n")
    html_footer += ("</body>\n")
    html_footer += ("</html>\n")

    ###########################
    # Fix up table of contents.
    ###########################
    html_toc_string = fuzz_html_helpers.html_get_table_of_contents(toc_list, coverage_url, profiles)

    # Assemble the final HTML report and write it to a file.
    html_full_doc = (html_header
                     + html_toc_string
                     + html_body_start
                     + html_overview
                     + html_report_top
                     + html_report_core
                     + html_body_end
                     + html_footer)

    # Pretty print the html document
    soup = bs(html_full_doc, "html.parser")
    prettyHTML = soup.prettify()

    # Remove existing html report
    report_name = "fuzz_report.html"
    if os.path.isfile(report_name):
        os.remove(report_name)

    # Write new html report
    with open(report_name, "a+") as html_report:
        html_report.write(prettyHTML)

    # Remove existing all funcs .js file
    report_name = "all_functions.js"
    if os.path.isfile(report_name):
        os.remove(report_name)

    # Write all functions to the .js file
    with open(report_name, "a+") as all_funcs_json_file:
        all_funcs_json_file.write("var all_functions_table_data = ")
        all_funcs_json_file.write(json.dumps(all_functions_json))

    # Remove existing fuzzer table data .js file
    js_file = "fuzzer_table_data.js"
    if os.path.isfile(js_file):
        os.remove(js_file)

    # Write fuzzer table data to the .js file
    with open(js_file, "a+") as fuzzer_table_data_file:
        fuzzer_table_data_file.write("var fuzzer_table_data = ")
        fuzzer_table_data_file.write(json.dumps(fuzzer_table_data))

    # Copy all of the styling into the directory.
    basedir = os.path.dirname(os.path.realpath(__file__))
    style_dir = os.path.join(basedir, "styling")
    for s in ["clike.js", "prism.css", "prism.js", "styles.css", "custom.js", "calltree.js"]:
        shutil.copy(os.path.join(style_dir, s), s)
