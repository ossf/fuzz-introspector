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

from typing import (
    Any,
    Callable,
    List,
    Tuple,
    NamedTuple,
    Optional,
    Set,
)

import fuzz_analysis
import fuzz_data_loader
import fuzz_utils
import fuzz_cfg_load

# For pretty printing the html code:
from bs4 import BeautifulSoup as bs

import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle

import random
import string

logger = logging.getLogger(name=__name__)


class AnalysisInterface(NamedTuple):
    name: str
    analysis_func: Callable


def create_horisontal_calltree_image(image_name: str,
                                     profile: fuzz_data_loader.FuzzerProfile) -> None:
    """
    Creates a horisontal image of the calltree. The height is fixed and
    each element on the x-axis shows a node in the calltree in the form
    of a rectangle. The rectangle is red if not visited and green if visited.
    """

    logger.info("Creating image %s" % image_name)

    if profile.function_call_depths is None:
        return
    # Extract color sequence
    color_list = []
    for node in fuzz_cfg_load.extract_all_callsites(profile.function_call_depths):
        color_list.append(node.cov_color)
    logger.info("- extracted the callsites (%d nodes)" % len(color_list))

    # Show one read rectangle if the list is empty. An alternative is
    # to not include the image at all.
    if len(color_list) == 0:
        color_list = ['red']
    plot_size = len(color_list)
    multiplier = plot_size / len(color_list)

    fig, ax = plt.subplots()
    ax.clear()
    fig.set_size_inches(15, 2)
    ax.plot()

    # Create our rectangles
    curr_start_x = 0.0
    curr_size = 1.0
    curr_color = color_list[0]

    for i in range(1, len(color_list)):
        if curr_color == color_list[i]:
            curr_size += 1.0
        else:
            final_start_x = curr_start_x * multiplier
            final_size = curr_size * multiplier
            ax.add_patch(Rectangle((final_start_x, 0.0), final_size, 1, color=curr_color))

            # Start next color area
            curr_start_x += curr_size
            curr_color = color_list[i]
            curr_size = 1.0
    logger.info("- iterated over color list")

    # Plot the last case
    final_start_x = curr_start_x * multiplier
    final_size = curr_size * multiplier
    ax.add_patch(Rectangle((final_start_x, 0.0), final_size, 1, color=curr_color))

    # Save the image
    logger.info("- saving image")
    plt.title(image_name.split(".")[0])
    plt.savefig(image_name)
    logger.info("- image saved")


def create_table_head(
        table_head: str,
        items: List[Tuple[str, str]],
        sort_by_column: int = 0,
        sort_order: str = "asc") -> str:
    html_str = (f"<table id='{table_head}' class='cell-border compact stripe' "
                f"data-sort-by-column='{sort_by_column}' data-sort-order='{sort_order}'>")
    html_str += "<thead><tr>\n"
    for column_title, column_description in items:
        if column_description == "":
            html_str += f"<th>{column_title}</th>\n"
        else:
            html_str += f"<th title='{column_description}'>{column_title}</th>\n"
    html_str += "</tr></thead><tbody>"
    return html_str


def html_table_add_row(elems: List[Any]) -> str:
    html_str = "<tr>\n"
    for elem in elems:
        html_str += f"<td>{elem}</td>\n"
    html_str += "</tr>\n"
    return html_str


def html_get_header() -> str:
    header = """<html>
    <head>
        <link
            rel='stylesheet'
            href='prism.css'>
        <link
            rel="stylesheet"
            href="https://unpkg.com/dracula-prism/dist/css/dracula-prism.css">
    </head>
        <body>
            <script
                src="https://code.jquery.com/jquery-3.6.0.min.js"
                integrity="sha256-/xUj+3OJU5yExlq6GSYGSHk7tPXikynS7ogEvDej/m4="
                crossorigin="anonymous">
            </script>
            <script
                src='https://cdn.datatables.net/1.10.25/js/jquery.dataTables.min.js'>
            </script>
            <link
                rel='stylesheet'
                href='https://cdn.datatables.net/1.10.25/css/jquery.dataTables.min.css'>
            <link
                rel='stylesheet'
                href='styles.css'>"""
    # Add navbar to header
    header = header + html_get_navbar()
    header = header + "<div class='content-wrapper'>"
    return header


def html_get_navbar() -> str:
    navbar = """<div class="top-navbar">
    <div class="top-navbar-accordion">
        <svg
            viewBox="0 0 24 24"
            preserveAspectRatio="xMidYMid meet"
            focusable="false"
            style="pointer-events: none; display: block; width: 100%; height: 100%;">
            <g>
                <path d="M3 18h18v-2H3v2zm0-5h18v-2H3v2zm0-7v2h18V6H3z">
                </path>
            </g>
        </svg>
    </div>
    <div class="top-navbar-title">
        Fuzz introspector
    </div>
</div>"""
    return navbar


def html_get_table_of_contents(toc_list: List[Tuple[str, str, int]]) -> str:
    html_toc_string = ""
    html_toc_string += '<div class="left-sidebar">\
                            <div class="left-sidebar-content-box">\
                                <h2>Table of contents</h2>'
    for k, v, d in toc_list:
        indentation = d * 16
        html_toc_string += "<div style='margin-left: %spx'>" % indentation
        html_toc_string += "    <a href=\"#%s\">%s</a>\n" % (v, k)
        html_toc_string += "</div>\n"
    html_toc_string += '    </div>\
                        </div>'
    return html_toc_string


def html_add_header_with_link(header_title: str,
                              title_type: int,
                              toc_list: List[Tuple[str, str, int]],
                              link: str = None) -> str:
    if link is None:
        link = header_title.replace(" ", "-")
    toc_list.append((header_title, link, title_type - 1))
    html_string = f"<a id=\"{link}\">"
    html_string += f"<h{title_type} class=\"report-title\">{header_title}</h{title_type}>\n"
    return html_string


def create_overview_table(tables: List[str],
                          profiles: List[fuzz_data_loader.FuzzerProfile]) -> str:
    """Table with an overview of all the fuzzers"""
    html_string = create_table_head(tables[-1], [
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

        html_string += html_table_add_row([
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
        git_repo_url: str,
        basefolder: str,
        table_id: str = None) -> str:
    """Table for all functions in the project. Contains many details about each
        function"""
    random_suffix = '_' + ''.join(
        random.choices(string.ascii_lowercase + string.ascii_uppercase, k=7))
    if table_id is None:
        table_id = tables[-1]
    html_string = create_table_head(table_id, [
        ("Func name",
         ""),
        ("Functions filename",
         "Source code file where function is defined."),
        ("Arg count",
         "Number of arguments to the function."),
        ("Args",
         "Types of arguments to this function."),
        ("Function call depth",
         "Function call depth based on static analysis."),
        ("Fuzzers reach count",
         "The number of fuzzers that reach this function. Based on static analysis."),
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
        ("Undiscovered complexity", "")])

    for fd_k, fd in project_profile.all_functions.items():
        demangled_func_name = fuzz_utils.demangle_cpp_func(fd.function_name)
        try:
            func_total_lines, hit_lines = project_profile.runtime_coverage.get_hit_summary(
                demangled_func_name
            )
            hit_percentage = (hit_lines / func_total_lines) * 100.0
        except Exception:
            hit_percentage = 0.0

        collapsible_id = demangled_func_name + random_suffix

        func_cov_url = "%s%s.html#L%d" % (
            coverage_url,
            fd.function_source_file,
            fd.function_linenumber
        )
        func_name_row = f"""<a href='{ func_cov_url }'><code class='language-clike'>
{ demangled_func_name }
</code></a>"""

        if demangled_func_name in project_profile.runtime_coverage.functions_hit:
            func_hit_at_runtime_row = "yes"
        else:
            func_hit_at_runtime_row = "no"

        if fd.reached_by_fuzzers:
            reached_by_fuzzers_row = f"""<div
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
                {fd.reached_by_fuzzers}
            </p>
        </div>
    </div>
</div>"""
        else:
            reached_by_fuzzers_row = "None"

        html_string += html_table_add_row([
            func_name_row,
            fd.function_source_file,
            fd.arg_count,
            fd.arg_types,
            fd.function_depth,
            fd.hitcount,
            reached_by_fuzzers_row,
            func_hit_at_runtime_row,
            "%.5s" % (str(hit_percentage)) + "%",
            fd.i_count,
            fd.bb_count,
            fd.cyclomatic_complexity,
            len(fd.functions_reached),
            len(fd.incoming_references),
            fd.total_cyclomatic_complexity,
            fd.new_unreached_complexity
        ])
    html_string += ("</table>\n")
    return html_string


def create_percentage_graph(title: str, percentage: str, numbers: str) -> str:
    return f"""<div style="flex:1; margin-right: 20px"class="report-box">
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


def create_boxed_top_summary_info(tables: List[str],
                                  project_profile: fuzz_data_loader.MergedProjectProfile,
                                  conclusions: List[Tuple[int, str]],
                                  extract_conclusion,
                                  display_coverage=False) -> str:
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
    graph1_numbers = "%d/%d" % (reached_func_count, total_functions)
    html_string += create_percentage_graph(graph1_title, graph1_percentage, graph1_numbers)

    graph2_title = "Cyclomatic complexity statically reachable by fuzzers"
    graph2_percentage = str(round(reached_complexity_percentage, 2))
    graph2_numbers = "%d/%d" % (complexity_reached, int(total_complexity))
    html_string += create_percentage_graph(graph2_title, graph2_percentage, graph2_numbers)
    if display_coverage:
        logger.info("Displaying coverage in summary")
        covered_funcs = project_profile.get_all_runtime_covered_functions()
        html_string += create_covered_func_box(str(len(covered_funcs)))

    # Add conclusion
    if extract_conclusion:
        create_conclusions(conclusions, reached_percentage, reached_complexity_percentage)
    return html_string


def create_conclusions(conclusions: List[Tuple[int, str]],
                       reached_percentage,
                       reached_complexity_percentage):
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
        sentence += "This is good, but improvements can be made"
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
        conclusions,
        extract_conclusion,
        display_coverage=False) -> str:
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
    graph1_numbers = "%d/%d" % (reached_func_count, total_functions)
    html_string += create_percentage_graph(graph1_title, graph1_percentage, graph1_numbers)

    graph2_title = "Cyclomatic complexity statically reachable by fuzzers"
    graph2_percentage = str(round(reached_complexity_percentage, 2))
    graph2_numbers = "%d / %d" % (complexity_reached, int(total_complexity))
    html_string += create_percentage_graph(graph2_title, graph2_percentage, graph2_numbers)
    html_string += "</div>"
    if display_coverage:
        logger.info("Displaying coverage in summary")
        covered_funcs = project_profile.get_all_runtime_covered_functions()
        html_string += f"""Functions covered at runtime: { len(covered_funcs) }"""
        html_string += "<br>"
    else:
        logger.info("Not displaying coverage in summary")

    # Add conclusion
    if extract_conclusion:
        create_conclusions(conclusions, reached_percentage, reached_complexity_percentage)

    return html_string


def write_wrapped_html_file(html_string, filename):
    """
    Write a wrapped HTML file with the tags needed from fuzz-introspector
    We use this only for wrapping calltrees at the moment, however, down
    the line it makes sense to have an easy wrapper for other HTML pages too.
    """
    complete_html_string = ""
    # HTML start
    html_header = html_get_header()
    html_header += '<div class="content-section">'
    complete_html_string += html_header

    complete_html_string += html_string
    complete_html_string += "</div></div></div></div>"

    # HTML end
    html_end = '</div>'
    html_end += "<script src=\"prism.js\"></script>"
    html_end += "<script src=\"clike.js\"></script>"
    html_end += "<script src=\"calltree.js\"></script>"
    complete_html_string += html_end

    complete_html_string += "</body></html>"

    soup = bs(complete_html_string, 'lxml')
    pretty_html = soup.prettify()

    with open(filename, "w+") as cf:
        cf.write(pretty_html)


def create_fuzz_blocker_table(
        profile: fuzz_data_loader.FuzzerProfile,
        project_profile: fuzz_data_loader.MergedProjectProfile,
        coverage_url: str,
        git_repo_url: str,
        basefolder: str,
        image_name: str,
        tables: List[str]) -> Optional[str]:
    """
    Creates HTML string for table showing fuzz blockers.
    """
    logger.info("Creating fuzz blocker table")
    # Identify if there are any fuzz blockers
    all_callsites = fuzz_cfg_load.extract_all_callsites(profile.function_call_depths)
    nodes_sorted_by_red_ahead = sorted(all_callsites,
                                       key=lambda x: x.cov_forward_reds,
                                       reverse=True)

    has_blockers = False
    for node in nodes_sorted_by_red_ahead:
        if node.cov_forward_reds > 0:
            has_blockers = True

    if not has_blockers:
        logger.info("There are no fuzz blockers")
        return None

    html_table_string = "<p class='no-top-margin'>The followings nodes " \
                        "represent call sites where fuzz blockers occur</p>"
    tables.append(f"myTable{len(tables)}")
    html_table_string += create_table_head(
        tables[-1],
        [
            ('Blocked nodes', ""),
            ('Calltree index', ""),
            ('Parent function', ""),
            ('Callsite', ""),
            ('Largest blocked function', "")
        ],
        sort_by_column=0,
        sort_order="desc"
    )
    max_idx = 10
    for node in nodes_sorted_by_red_ahead:
        if max_idx == 0 or node.cov_forward_reds == 0:
            break
        html_table_string += html_table_add_row([
            str(node.cov_forward_reds),
            str(node.cov_ct_idx),
            node.cov_parent,
            "<a href=%s>call site</a>" % node.cov_callsite_link,
            node.cov_largest_blocked_func
        ])
        max_idx -= 1
    html_table_string += "</table>"

    return html_table_string


def create_calltree(
        profile: fuzz_data_loader.FuzzerProfile,
        project_profile: fuzz_data_loader.MergedProjectProfile,
        coverage_url: str,
        git_repo_url: str,
        basefolder: str,
        image_name: str,
        tables: List[str]) -> str:
    """
    Creates the HTML of the calltree. Returns the HTML as a string.
    """
    logger.info("Creating calltree HTML code")
    # Generate HTML for the calltree
    calltree_html_string = "<div class='section-wrapper'>"
    nodes = fuzz_cfg_load.extract_all_callsites(profile.function_call_depths)
    for i in range(len(nodes)):
        node = nodes[i]

        demangled_name = fuzz_utils.demangle_cpp_func(node.dst_function_name)
        # We may not want to show certain functions at times, e.g. libc functions
        # in case it bloats the calltree
        # libc_funcs = { "free" }
        libc_funcs: Set[str] = set()
        avoid = len([fn for fn in libc_funcs if fn in demangled_name]) > 0
        if avoid:
            continue

        # Prepare strings needed in the HTML
        color_to_be = node.cov_color
        callsite_link = node.cov_callsite_link
        link = node.cov_link
        ct_idx_str = "%s%s" % ("0" * (len("00000") - len(str(node.cov_ct_idx))),
                               str(node.cov_ct_idx))

        # Only display [function] link if we have, otherwhise show no [function] text.
        if node.dst_function_source_file.replace(" ", "") != "/":
            func_href = f"""<a href="{link}">[function]</a>"""
        else:
            func_href = ""

        if i > 0:
            previous_node = nodes[i - 1]
            if previous_node.depth == node.depth:
                calltree_html_string += "</div>"
            depth_diff = previous_node.depth - node.depth
            if depth_diff >= 1:
                closing_divs = "</div>"  # To close "calltree-line-wrapper"
                closing_divs = "</div>" * (int(depth_diff) + 1)
                calltree_html_string += closing_divs

        calltree_html_string += f"""
<div class="{color_to_be}-background coverage-line">
    <span class="coverage-line-inner">
        {node.depth}
        <code class="language-clike">
            {demangled_name}
        </code>
        <span class="coverage-line-filename">
            {func_href}
            <a href="{callsite_link}">
                [call site2]
            </a>
            [calltree idx: {ct_idx_str}]
        </span>
    </span>
    """
        if i != len(nodes) - 1:
            next_node = nodes[i + 1]
            if next_node.depth > node.depth:
                calltree_html_string += f"""<div
    class="calltree-line-wrapper open level-{int(node.depth)}"
    style="padding-left: 16px">"""
            elif next_node.depth < node.depth:
                depth_diff = int(node.depth - next_node.depth)
                calltree_html_string += "</div>" * depth_diff

    calltree_html_string += "</div>"
    logger.info("Calltree created")

    # Write the HTML to a file called calltree_view_XX.html where XX is a counter.
    calltree_file_idx = 0
    calltree_html_file = "calltree_view_%d.html" % calltree_file_idx
    while os.path.isfile(calltree_html_file):
        calltree_file_idx += 1
        calltree_html_file = "calltree_view_%d.html" % calltree_file_idx

    write_wrapped_html_file(calltree_html_string, calltree_html_file)
    return calltree_html_file


def create_fuzzer_detailed_section(
        profile: fuzz_data_loader.FuzzerProfile,
        toc_list: List[Tuple[str, str, int]],
        tables: List[str],
        curr_tt_profile: int,
        project_profile: fuzz_data_loader.MergedProjectProfile,
        coverage_url: str,
        git_repo_url: str,
        basefolder: str,
        conclusions, extract_conclusion) -> str:
    html_string = ""
    fuzzer_filename = profile.fuzzer_source_file

    html_string += html_add_header_with_link("Fuzzer: %s" % (
        profile.get_key()),
        2,
        toc_list
    )

    # Calltree fixed-width image
    html_string += html_add_header_with_link(
        "Call tree overview", 3, toc_list, link=f"call_tree_{curr_tt_profile}")
    html_string += """<p class='no-top-margin'>
 The following is the call tree with color coding for which
 functions are hit/not hit. This info is based on the coverage
 achieved of all fuzzers together and not just this specific
 fuzzer. This should change in the future to be per-fuzzer-basis.
</p>"""
    image_name = "%s_colormap.png" % (fuzzer_filename.replace(" ", "").split("/")[-1])

    create_horisontal_calltree_image(image_name, profile)
    html_string += "<img class=\"colormap\" src=\"%s\">" % image_name

    # Full calltree
    html_string += html_add_header_with_link(
        "Full calltree",
        3,
        toc_list,
        link=f"full_calltree_{curr_tt_profile}"
    )
    calltree_file_name = create_calltree(
        profile,
        project_profile,
        coverage_url,
        git_repo_url,
        basefolder,
        image_name,
        tables
    )
    html_string += f"""<p class='no-top-margin'>The following link provides a visualisation
 of the full calltree overlayed with coverage information:
 <a href="{ calltree_file_name }">full calltree</a></p>"""

    # Fuzz blocker table
    html_fuzz_blocker_table = create_fuzz_blocker_table(profile,
                                                        project_profile,
                                                        coverage_url,
                                                        git_repo_url,
                                                        basefolder,
                                                        image_name,
                                                        tables)
    if html_fuzz_blocker_table is not None:
        html_string += html_add_header_with_link(
            "Fuzz blockers",
            3,
            toc_list,
            link=f"fuzz_blocker{curr_tt_profile}"
        )
        html_string += html_fuzz_blocker_table

    # Table with all functions hit by this fuzzer
    html_string += html_add_header_with_link(
        "Functions hit (dynamic analysis based)",
        3,
        toc_list,
        link="functions_cov_hit_%d" % curr_tt_profile
    )
    tables.append(f"myTable{len(tables)}")
    func_hit_table_string = ""
    func_hit_table_string += create_table_head(
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
             hit_percentage) = profile.get_cov_metrics(fuzz_utils.demangle_cpp_func(funcname))
            if hit_percentage is not None:
                total_hit_functions += 1
                func_hit_table_string += html_table_add_row([
                    funcname,
                    total_func_lines,
                    hit_lines,
                    "%.5s" % (str(hit_percentage)) + "%"])
            else:
                logger.error("Could not write coverage line for function %s" % funcname)
    func_hit_table_string += "</table>"

    # Get how many functions are covered relative to reachability
    uncovered_reachable_funcs = len(profile.get_cov_uncovered_reachable_funcs())
    reachable_funcs = len(profile.functions_reached_by_fuzzer)
    reached_funcs = reachable_funcs - uncovered_reachable_funcs
    cov_reach_proportion = (float(reached_funcs) / float(reachable_funcs)) * 100.0

    if extract_conclusion:
        if cov_reach_proportion < 30.0:
            str_percentage = "%.5s%%" % str(cov_reach_proportion)
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
                   "that are reachable but not covered</i> need not be <i>Reachable " \
                   "functions</i>. This is because the reachability analysis is an "  \
                   "approximation and thus at runtime some functions may be covered " \
                   "that are not included in the reachability analysis. This is a "   \
                   "limitation our of our static analysis capabilities."
    html_string += "</div>"

    html_string += func_hit_table_string

    # Table showing which files this fuzzer hits.
    html_string += html_add_header_with_link(
        "Files hit", 3, toc_list, link="files_hit_%d" % (curr_tt_profile))
    tables.append(f"myTable{len(tables)}")
    html_string += create_table_head(
        tables[-1],
        [
            ("filename", ""),
            ("functions hit", "")
        ])
    for k in profile.file_targets:
        html_string += html_table_add_row([k,
                                          len(profile.file_targets[k])])
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


def handle_analysis_3(toc_list: List[Tuple[str, str, int]],
                      tables: List[str],
                      project_profile: fuzz_data_loader.MergedProjectProfile,
                      profiles: List[fuzz_data_loader.FuzzerProfile],
                      basefolder: str,
                      git_repo_url: str,
                      coverage_url: str,
                      conclusions) -> str:
    logger.info("In analysis 3")

    functions_of_interest = fuzz_analysis.analysis_coverage_runtime_analysis(
        profiles,
        project_profile
    )

    html_string = ""
    html_string += "<div class=\"report-box\">"
    html_string += html_add_header_with_link(
        "Runtime coverage analysis",
        1,
        toc_list
    )
    html_string += "<p>This section gives analysis based on data about the runtime " \
                   "coverage information</p>"

    html_string += html_add_header_with_link(
        "Complex functions with low coverage", 3, toc_list)
    tables.append("myTable%d" % (len(tables)))
    html_string += create_table_head(
        tables[-1],
        [
            ("Func name", ""),
            ("lines of code", ""),
            ("LoC runtime coverage", ""),
            ("percentage covered", "")
        ])

    for funcname in functions_of_interest:
        total_func_lines, hit_lines = project_profile.runtime_coverage.get_hit_summary(funcname)
        html_string += html_table_add_row([
            fuzz_utils.demangle_cpp_func(funcname),
            total_func_lines,
            hit_lines,
            "%.5s" % (str((hit_lines / total_func_lines) * 100.0))
        ])
    html_string += "</table>"
    html_string += "</div>"  # report-box
    return html_string


def handle_analysis_2(toc_list: List[Tuple[str, str, int]],
                      tables: List[str],
                      project_profile: fuzz_data_loader.MergedProjectProfile,
                      profiles: List[fuzz_data_loader.FuzzerProfile],
                      basefolder: str,
                      git_repo_url: str,
                      coverage_url: str,
                      conclusions) -> str:
    logger.info("In analysis 2")

    html_string = ""
    html_string += html_add_header_with_link(
        "Fuzz engine guidance", 1, toc_list)
    html_string += "<p>This sections provides heuristics that can be used as input " \
                   "to a fuzz engine when running a given fuzz target. The current " \
                   "focus is on providing input that is usable by libFuzzer.</p>"

    for profile_idx in range(len(profiles)):
        html_string += html_add_header_with_link(
            "%s" % (profiles[profile_idx].fuzzer_source_file),
            2,
            toc_list)
        html_string += html_add_header_with_link("Dictionary", 3, toc_list)
        html_string += "<p>Use this with the libFuzzer -dict=DICT.file flag</p>"

        html_string += "<pre><code class='language-clike'>"
        kn = 0
        for fn in profiles[profile_idx].functions_reached_by_fuzzer:
            fp = profiles[profile_idx].all_class_functions[fn]
            for const in fp.constants_touched:
                html_string += "k%d=\"%s\"\n" % (kn, const)
                kn += 1
        html_string += "</code></pre><br>"

        html_string += html_add_header_with_link(
            "Fuzzer function priority",
            3,
            toc_list
        )
        html_string += "<p>Use this as input to libfuzzer with flag: -focus_function=FUNC_NAME</p>"
        html_string += "<pre><code class='language-clike'>TBD</code></pre><br>"

    return html_string


def handle_analysis_1(toc_list: List[Tuple[str, str, int]],
                      tables: List[str],
                      project_profile: fuzz_data_loader.MergedProjectProfile,
                      profiles: List[fuzz_data_loader.FuzzerProfile],
                      basefolder: str,
                      git_repo_url: str,
                      coverage_url: str,
                      conclusions) -> str:
    """
    Performs an analysis based on optimal target selection.

    Finds a set of optimal functions based on complexity reach and:
      - Displays the functions in a table.
      - Calculates how the new all-function table will be in case the optimal
        targets are implemented.
      - Performs a simple synthesis on how to create fuzzers that target the
        optimal functions.

    The "optimal target function" is focused on code that is currently *not hit* by
    any fuzzers. This means it can be used to expand the current fuzzing harness
    rather than substitute it.
    """
    logger.info(" - Identifying optimal targets")

    html_string = ""
    html_string += html_add_header_with_link(
        "Optimal target analysis", 2, toc_list)
    (fuzz_targets,
     new_profile,
     optimal_target_functions) = fuzz_analysis.analysis_synthesize_simple_targets(
        project_profile
    )

    html_string += "<p>If you implement fuzzers that target the "          \
                   "<a href=\"#Remaining-optimal-interesting-functions\">" \
                   "remaining optimal functions</a> then the reachability will be:</p>"
    tables.append(f"myTable{len(tables)}")
    html_string += create_top_summary_info(tables, new_profile, conclusions, False)

    # Table with details about optimal target functions
    html_string += html_add_header_with_link(
        "Remaining optimal interesting functions", 3, toc_list)
    table_id = "remaining_optimal_interesting_functions"
    tables.append(table_id)
    html_string += create_table_head(table_id,
                                     [
                                         ("Func name", ""),
                                         ("Functions filename", ""),
                                         ("Arg count", ""),
                                         ("Args", ""),
                                         ("Function depth", ""),
                                         ("hitcount", ""),
                                         ("instr count", ""),
                                         ("bb count", ""),
                                         ("cyclomatic complexity", ""),
                                         ("Reachable functions", ""),
                                         ("Incoming references", ""),
                                         ("total cyclomatic complexity", ""),
                                         ("Unreached complexity", "")
                                     ])
    for fd in optimal_target_functions:
        html_string += html_table_add_row([
            "<a href=\"#\"><code class='language-clike'>%s</code></a>" % (
                fuzz_utils.demangle_cpp_func(fd.function_name)),
            fd.function_source_file,
            fd.arg_count,
            fd.arg_types,
            fd.function_depth,
            fd.hitcount,
            fd.i_count,
            fd.bb_count,
            fd.cyclomatic_complexity,
            len(fd.functions_reached),
            len(fd.incoming_references),
            fd.total_cyclomatic_complexity,
            fd.new_unreached_complexity])
    html_string += ("</table>\n")

    # Section with code for new fuzzing harnesses
    html_string += html_add_header_with_link("New fuzzers", 3, toc_list)
    html_string += "<p>The below fuzzers are templates and suggestions for how " \
                   "to target the set of optimal functions above</p>"
    for filename in fuzz_targets:
        html_string += html_add_header_with_link("%s" %
                                                 (filename.split("/")[-1]), 4, toc_list)
        html_string += "<b>Target file:</b>%s<br>" % (filename)
        all_functions = ", ".join([f.function_name for f in fuzz_targets[filename]['target_fds']])
        html_string += "<b>Target functions:</b> %s" % (all_functions)
        html_string += "<pre><code class='language-clike'>%s</code></pre><br>" % (
            fuzz_targets[filename]['source_code'])

    # Table overview with how reachability is if the new fuzzers are applied.
    html_string += html_add_header_with_link(
        "Function reachability if adopted", 3, toc_list)
    tables.append("myTable%d" % (len(tables)))
    html_string += create_top_summary_info(tables, new_profile, conclusions, False)

    # Table with details about all functions in the project in case the
    # suggested fuzzers are implemented.
    html_string += html_add_header_with_link(
        "All functions overview", 4, toc_list)
    table_id = "all_functions_overview_table"
    tables.append(table_id)
    html_string += create_all_function_table(
        tables, new_profile, coverage_url, git_repo_url, basefolder, table_id)
    html_string += "</div>"  # close report-box

    return html_string


def extract_highlevel_guidance(conclusions) -> str:
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
    <span class="high-level-conclusion { conclusion_color }-conclusion">
    { sentence }
    </span>
</div>"""
    html_string += "</div>"
    return html_string


def create_html_report(
        profiles: List[fuzz_data_loader.FuzzerProfile],
        project_profile: fuzz_data_loader.MergedProjectProfile,
        analyses_to_run: List[str],
        coverage_url: str,
        git_repo_url: str,
        basefolder: str) -> None:
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
    html_header = html_get_header()

    # Start creation of core html
    html_body_start = '<div class="content-section">'
    html_overview = html_add_header_with_link("Project overview", 1, toc_list)

    # Project overview
    # html_overview += html_add_header_with_link("Project information", 2, toc_list)

    #############################################
    # Section with high level suggestions
    #############################################
    html_report_top = html_add_header_with_link(
        "High level conclusions", 3, toc_list)

    #############################################
    # Reachability overview
    #############################################
    logger.info(" - Creating reachability overview table")
    html_report_core = html_add_header_with_link("Reachability and coverage overview", 3, toc_list)
    tables.append("myTable%d" % (len(tables)))
    html_report_core += "<div style=\"display: flex; max-width: 800px\">"
    html_report_core += create_boxed_top_summary_info(
        tables,
        project_profile,
        conclusions,
        True,
        display_coverage=True
    )
    html_report_core += "</div>"

    #############################################
    # Table with overview of all fuzzers.
    #############################################
    logger.info(" - Creating table with overview of all fuzzers")
    html_report_core += html_add_header_with_link("Fuzzers overview", 3, toc_list)
    tables.append("myTable%d" % (len(tables)))
    html_report_core += create_overview_table(tables, profiles)

    #############################################
    # Table with details about all functions in the target project.
    #############################################
    logger.info(" - Creating table with information about all functions in target")
    html_report_core += "<div class=\"report-box\">"
    html_report_core += html_add_header_with_link(
        "Project functions overview", 2, toc_list)
    table_id = "fuzzers_overview_table"
    tables.append(table_id)
    html_report_core += create_all_function_table(
        tables, project_profile, coverage_url, git_repo_url, basefolder, table_id)
    html_report_core += "</div>"  # report box

    #############################################
    # Section with details about each fuzzer, including calltree.
    #############################################
    logger.info(" - Creating section with details about each fuzzer")
    html_report_core += "<div class=\"report-box\">"
    html_report_core += html_add_header_with_link("Fuzzer details", 1, toc_list)
    for profile_idx in range(len(profiles)):
        html_report_core += create_fuzzer_detailed_section(
            profiles[profile_idx],
            toc_list,
            tables,
            profile_idx,
            project_profile,
            coverage_url,
            git_repo_url,
            basefolder,
            conclusions,
            True
        )
    html_report_core += "</div>"  # report box

    #############################################
    # Handle optional analyses
    #############################################
    logger.info(" - Handling optional analyses")
    html_report_core += "<div class=\"report-box\">"
    html_report_core += html_add_header_with_link(
        "Analyses and suggestions", 1, toc_list)

    # Ordering here is important as top analysis will be shown first in the report
    analysis_array = [
        AnalysisInterface("OptimalTargets", handle_analysis_1),
        AnalysisInterface("FuzzEngineInput", handle_analysis_2),
        AnalysisInterface("OptimalCoverageTargets", handle_analysis_3)
    ]

    for analysis in analysis_array:
        if analysis.name in analyses_to_run:
            html_report_core += analysis.analysis_func(
                toc_list,
                tables,
                project_profile,
                profiles,
                basefolder,
                git_repo_url,
                coverage_url,
                conclusions)
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

    # Add PrismJs for code snippet styling
    html_body_end += "<script src=\"prism.js\"></script>"
    html_body_end += "<script src=\"clike.js\"></script>"
    html_body_end += "<script src=\"custom.js\"></script>"

    ###########################
    # Footer
    ###########################
    html_footer = "<script>\n"

    # Create array of all table ids
    html_footer += "var tableIds = ["
    counter = 0
    for tablename in tables:
        html_footer += "'%s'" % tablename
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
    html_toc_string = html_get_table_of_contents(toc_list)

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
    soup = bs(html_full_doc, "lxml")
    prettyHTML = soup.prettify()

    # Remove existing html report
    report_name = "fuzz_report.html"
    if os.path.isfile(report_name):
        os.remove(report_name)

    # Write new html report
    with open(report_name, "a+") as html_report:
        html_report.write(prettyHTML)

    # Copy all of the styling into the directory.
    basedir = os.path.dirname(os.path.realpath(__file__))
    style_dir = os.path.join(basedir, "styling")
    for s in ["clike.js", "prism.css", "prism.js", "styles.css", "custom.js", "calltree.js"]:
        shutil.copy(os.path.join(style_dir, s), s)
