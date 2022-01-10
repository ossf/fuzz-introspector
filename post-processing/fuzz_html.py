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
import sys
import cxxfilt
import logging
import shutil

from typing import (
    Any,
    Dict,
    List,
    Tuple,
)

import fuzz_analysis
import fuzz_data_loader
import fuzz_utils

# For pretty printing the html code:
from bs4 import BeautifulSoup as bs
import lxml.html as lh

import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle

l = logging.getLogger(name=__name__)

def create_horisontal_calltree_image(image_name: str, color_list: List[str]) -> None:
    """
    Creates a horisontal image of the calltree. The height is fixed and 
    each element on the x-axis shows a node in the calltree in the form
    of a rectangle. The rectangle is red if not visited and green if visited.
    """
    l.info("Creating image %s"%(image_name))
    plot_size = 10.0
    multiplier = plot_size / len(color_list)

    fig, ax = plt.subplots()
    ax.clear()
    fig.set_size_inches(20, 2)
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
            final_end_x = final_start_x + curr_size * multiplier
            final_size = curr_size * multiplier
            ax.add_patch(Rectangle((final_start_x, 0.0), final_size, 1, color=curr_color))

            # Start next color area
            curr_start_x += curr_size
            curr_color = color_list[i]
            curr_size = 1.0

    # Plot the last case
    final_start_x = curr_start_x * multiplier
    final_end_x = final_start_x + curr_size * multiplier
    final_size = curr_size * multiplier
    ax.add_patch(Rectangle((final_start_x, 0.0), final_size, 1, color=curr_color))

    # Save the image
    plt.title(image_name.split(".")[0])
    plt.savefig(image_name)

def normalise_str(s1: str) -> str:
    return s1.replace("\t", "").replace("\r", "").replace("\n", "").replace(" ", "")

def create_table_head(table_head: str, items: List[str]) -> str:
    html_str = f"<table id='{table_head}' class='cell-border compact stripe'><thead><tr>\n"
    #html_str = ""
    for elem in items:
        html_str += f"<th>{elem}</th>\n"
    html_str += "</tr></thead><tbody>"
    return html_str

def html_table_add_row(elems: List[str]) -> str:
    html_str = "<tr>\n"
    for elem in elems:
        html_str += f"<td>{elem}</td>\n"
    html_str += "</tr>\n"
    return html_str

def html_get_header() -> str:
    header = """<html>
                <head>
                    <link rel='stylesheet' href='prism.css'>
                    <link rel="stylesheet" href="https://unpkg.com/dracula-prism/dist/css/dracula-prism.css">
                </head>
                <body>
                    <script src="https://code.jquery.com/jquery-3.6.0.min.js" integrity="sha256-/xUj+3OJU5yExlq6GSYGSHk7tPXikynS7ogEvDej/m4=" crossorigin="anonymous"></script>
                    <script src='https://cdn.datatables.net/1.10.25/js/jquery.dataTables.min.js'></script>
                    <link rel='stylesheet' href='https://cdn.datatables.net/1.10.25/css/jquery.dataTables.min.css'>
                    <link rel='stylesheet' href='styles.css'>"""
    # Add navbar to header
    header = header+html_get_navbar()
    header = header+"<div class='content-wrapper'>"
    return header

def html_get_navbar() -> str:
    navbar = """\n<div class="top-navbar">\n
                    <div class="top-navbar-accordion">\n
                        <svg viewBox="0 0 24 24" preserveAspectRatio="xMidYMid meet" focusable="false" style="pointer-events: none; display: block; width: 100%; height: 100%;">
                            <g>
                                <path d="M3 18h18v-2H3v2zm0-5h18v-2H3v2zm0-7v2h18V6H3z">
                                </path>
                            </g>
                        </svg>\n
                    </div>\n
                    <div class="top-navbar-title">\n
                        Fuzz introspector\n
                    </div>\n
                </div>\n"""
    return navbar

def html_get_table_of_contents(toc_list: List[Tuple[str, str, str]]) -> str:
    html_toc_string = ""
    html_toc_string += '<div class="left-sidebar">\
                            <div class="left-sidebar-content-box">\
                                <h2>Table of contents</h2>'
    for k, v, d in toc_list:
        indentation = d*16
        html_toc_string += "<div style='margin-left: %spx'>"%(indentation)
        html_toc_string += "    <a href=\"#%s\">%s</a>\n" % (v, k)
        html_toc_string += "</div>\n"
    html_toc_string += '    </div>\
                        </div>'
    return html_toc_string


def html_add_header_with_link(header_title: str,
                                  title_type: int,
                                  toc_list: List[Tuple[str, str, str]],
                                  link: str=None) -> str:
    if link == None:
        link = header_title.replace(" ", "-")
    toc_list.append((header_title, link, title_type-1))
    html_string = f"<a id=\"{link}\">"
    html_string += f"<h{title_type}>{header_title}</h{title_type}>\n"
    return html_string


def create_overview_table(tables: List[str],
                              profiles: List[fuzz_data_loader.FuzzerProfile]) -> str:
    """Table with an overview of all the fuzzers"""
    html_string = create_table_head(tables[-1],
                                    ["Fuzzer filename",
                                     "Functions Reached",
                                     "Functions unreached",
                                     "Fuzzer depth",
                                     "Files reached",
                                     "Basic blocks reached",
                                     "Cyclomatic complexity",
                                     "Details"])
    for profile in profiles:  # create a row for each fuzzer.
        fuzzer_filename = profile.fuzzer_source_file
        max_depth = 0
        for node in profile.function_call_depths:
            if node['depth'] > max_depth:
                max_depth = node['depth']

        html_string += html_table_add_row([
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
        basefolder: str) -> str:
    """Table for all functions in the project. Contains many details about each
        function"""
    html_string = create_table_head(tables[-1],
                                    ["Func name", "Git URL", "Functions filename", "Arg count", "Args",
                                     "Function reach depth", "Fuzzers hit count", "I Count", "BB Count",
                                     "Cyclomatic complexity", "Functions reached",
                                     "Reached by functions", "Accumulated cyclomatic complexity",
                                     "Undiscovered complexity"])

    if basefolder == "/":
        basefolder = "WRONG"

    for fd_k, fd in project_profile.all_functions.items():
        if basefolder == "WRONG":
            fd_github_url = "%s/%s#L%d" % (git_repo_url, "/".join(
                fd.function_source_file.split("/")[3:]), fd.function_linenumber)
        else:
            fd_github_url = "%s/%s#L%d" % (git_repo_url, fd.function_source_file.replace(
                basefolder, ""), fd.function_linenumber)
        html_string += html_table_add_row([
            "%s" % ("<a href='%s'><code class='language-clike'>" % ("%s%s.html#L%d" % (coverage_url,
                    fd.function_source_file, fd.function_linenumber)) + fuzz_utils.demangle_cpp_func(fd.function_name) + "</code></a>"),
            "<a href=\"%s\">LINK</a>" % (fd_github_url),
            "%s" % fd.function_source_file,
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
            fd.new_unreached_complexity
        ])
    html_string += ("</table>\n")
    return html_string


def create_top_summary_info(
        tables: List[str],
        project_profile: fuzz_data_loader.MergedProjectProfile) -> str:
    html_string = ""
    total_unreached_functions = set()
    total_reached_functions = set()

    for fd_k, fd in project_profile.all_functions.items():
        if fd.hitcount == 0:
            total_unreached_functions.add(fd.function_name)
        else:
            total_reached_functions.add(fd.function_name)

    # Get the total amount of compleixty reached
    total_complexity_reached, total_complexity_unreached = project_profile.get_total_complexity()

    html_string += create_table_head(tables[-1],
                                     ["", "Reached", "Unreached"])

    functions_percentage = ((len(total_reached_functions)*1.0) / (len(total_reached_functions) + len(
        total_unreached_functions)*1.0))*100
    complexity_percentage = (total_complexity_reached / (total_complexity_reached + total_complexity_unreached))*100

    unreached_functions = len(total_unreached_functions)
    reached_functions = len(total_reached_functions)
    total_functions = unreached_functions + reached_functions
    reached_funcs_percentage = reached_functions*1.0 / (1.0 * total_functions)
    unreached_funcs_percentage = ((unreached_functions*1.0) / ((1.0*total_functions))) * 100.0

    total_complexity = total_complexity_unreached + total_complexity_reached
    reached_complexity_percentage = (total_complexity_reached*1.0 / (total_complexity * 1.0)) * 100.0
    unreached_complexity_percentage = (total_complexity_unreached*1.0 / (total_complexity*1.0)) * 100.0

    html_string += html_table_add_row([
        "Functions", 
        "%.5s%% (%d / %d)"%(str(functions_percentage),reached_functions,total_functions),
        "%.5s%% (%d / %d)"%(str(unreached_funcs_percentage), unreached_functions,total_functions)
        ])
    html_string += html_table_add_row([
        "Complexity", 
        "%.5s%% (%d / %d)"%(reached_complexity_percentage,total_complexity_reached,total_complexity),
        "%.5s%% (%d / %d)"%(unreached_complexity_percentage,total_complexity_unreached,total_complexity)        
        ])
    html_string += ("</table>\n")
    return html_string


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

    # Overlay statically extracted calltree with runtime coverage information
    fuzz_analysis.overlay_calltree_with_coverage(profile, project_profile, coverage_url, git_repo_url, basefolder, image_name)
 
    # Highlight the ten most useful places
    nodes_sorted_by_red_ahead = list(reversed(list(sorted(profile.function_call_depths, key=lambda x:x['cov-forward-reds']))))
    max_idx = 10
    html_string = create_table_head(tables[-1], ['Blocked nodes', 'Calltree index', 'Parent function', 'Callsite', 'Largest blocked function'])
    for node in nodes_sorted_by_red_ahead:
        html_string += html_table_add_row([str(node['cov-forward-reds']), str(node['cov-ct-idx']), node['cov-parent'], "<a href=%s>call site</a>"%(node['cov-callsite-link']), node['cov-largest-blocked-func']])
        if max_idx == 0:
            break
        max_idx -= 1
    html_string += "</table>"

    # Generate calltree overlay HTML
    html_string += "<div class='section-wrapper'>"
    for node in profile.function_call_depths:
        demangled_name = fuzz_utils.demangle_cpp_func(node['function_name'])
        color_to_be = node['cov-color']
        callsite_link = node['cov-callsite-link']
        link = node['cov-link']

        # We may not want to show certain functions at times, e.g. libc functions
        # in case it bloats the calltree
        #libc_funcs = { "free" }
        libc_funcs = { }
        should_do = len([fn for fn in libc_funcs if fn in demangled_name]) == 0
        if not should_do:
            continue

        # Create the HTML code for the line in the calltree
        ct_idx_str = "%s%s"%("0"*(len("00000") - len(str(node['cov-ct-idx']))), str(node['cov-ct-idx']))

        indentation = int(node['depth'])*16
        horisontal_spacing = "&nbsp;"*4*int(node['depth'])
        html_string += "<div style='margin-left: %spx' class=\"%s-background\">"%(str(indentation), color_to_be)
        html_string += "<span class=\"coverage-line-inner\">%d <code class=\"language-clike\">%s</code>"%(int(node['depth']), demangled_name)

        if node['functionSourceFile'].replace(" ","") == "/":
            func_href = ""
        else:
            func_href = "<a href=\"%s\">[function]</a>"%(link)

        html_string += "<span class=\"coverage-line-filename\">%s<a href=\"%s\">[call site2]</a>[calltree idx: %s]<span></span></div>\n"%(func_href, callsite_link, ct_idx_str)
    html_string += "</div>"

    # Create fixed-width color sequence image
    color_sequence = []
    for node in profile.function_call_depths:
        color_sequence.append(node['cov-color'])
    create_horisontal_calltree_image(image_name, color_sequence)
    return html_string

def create_fuzzer_detailed_section(
        profile: fuzz_data_loader.FuzzerProfile,
        toc_list: List[Tuple[str, str, int]],
        tables: List[str],
        curr_tt_profile: int,
        project_profile: fuzz_data_loader.MergedProjectProfile,
        coverage_url: str,
        git_repo_url: str,
        basefolder: str) -> str:
    html_string = ""
    fuzzer_filename = profile.fuzzer_source_file
    html_string += html_add_header_with_link("Fuzzer: %s" % (
        fuzzer_filename.replace(" ", "").split("/")[-1]), 2, toc_list)

    html_string += html_add_header_with_link(
        "Files hit", 3, toc_list, link="files_hit_%d" % (curr_tt_profile))

    # Table showing which files this fuzzer hits.
    tables.append(f"myTable{len(tables)}")
    html_string += create_table_head(tables[-1],
                                     ["filename", "functions hit"])
    for k in profile.file_targets:
        html_string += html_table_add_row([k,
                                          len(profile.file_targets[k])])
    html_string += "</table>\n"

    # Calltree generation
    html_string += html_add_header_with_link(
        "Call tree", 3, toc_list, link=f"call_tree_{curr_tt_profile}")
    html_string += "<h4>Function coverage</h4>"
    html_string += ("<p class='no-top-margin'>The following is the call tree with color coding for which "
                    "functions are hit/not hit. This info is based on the coverage "
                    "achieved of all fuzzers together and not just this specific "
                    "fuzzer. This should change in the future to be per-fuzzer-basis.</p>")
    image_name = "%s_colormap.png"%(fuzzer_filename.replace(" ", "").split("/")[-1])
    html_string += "<img src=\"%s\">"%(image_name)

    #html_string += "<div class='section-wrapper'>"
    tables.append(f"myTable{len(tables)}")
    html_string += create_calltree(profile, project_profile, coverage_url, git_repo_url, basefolder, image_name, tables)
    #html_string += "</div>"

    return html_string

def handle_analysis_1(
	    toc_list: List[Tuple[str, str, int]],
            tables: List[str],
            project_profile: fuzz_data_loader.MergedProjectProfile,
            basefolder: str,
            git_repo_url: str,
            coverage_url: str) -> str:
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
    l.info(" - Identifying optimal targets")

    html_string = ""
    html_string += html_add_header_with_link(
        "Optimal target analysis", 2, toc_list)
    fuzz_targets, new_profile, optimal_target_functions = fuzz_analysis.analysis_synthesize_simple_targets(
        project_profile)
    html_string += "<p>If you implement fuzzers that target the <a href=\"#Remaining-optimal-interesting-functions\">remaining optimal functions</a> then the reachability will be:</p>"
    tables.append(f"myTable{len(tables)}")
    html_string += create_top_summary_info(tables, new_profile)

    # Table with details about optimal target functions
    html_string += html_add_header_with_link(
        "Remaining optimal interesting functions", 3, toc_list)
    tables.append("myTable%d" % (len(tables)))
    html_string += create_table_head(tables[-1],
                                     ["Func name", "Functions filename", "Arg count", "Args", "Function depth", "hitcount", "instr count", "bb count", "cyclomatic complexity", "Reachable functions", "Incoming references", "total cyclomatic complexity", "Unreached complexity"])
    for fd in optimal_target_functions:
        if basefolder == "/":
            basefolder = "WRONG"

        if basefolder == "WRONG":
            fd_github_url = "%s/%s#L%d" % (git_repo_url, "/".join(
                fd['functionSourceFile'].split("/")[3:]), fd.function_linenumber)
        else:
            fd_github_url = "%s/%s#L%d" % (git_repo_url, fd.function_source_file.replace(
                basefolder, ""), fd.function_linenumber)

        html_string += html_table_add_row([
            "<a href=\"%s\"><code class='language-clike'>%s</code></a>" % (
                fd_github_url, fuzz_utils.demangle_cpp_func(fd.function_name)),
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
    html_string += "<p>The below fuzzers are templates and suggestions for how to target the set of optimal functions above</p>"
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
    html_string += create_top_summary_info(tables, new_profile)

    # Table with details about all functions in the project in case the
    # suggested fuzzers are implemented.
    html_string += html_add_header_with_link(
        "All functions overview", 4, toc_list)
    tables.append("myTable%d" % (len(tables)))
    html_string += create_all_function_table(
        tables, new_profile, coverage_url, git_repo_url, basefolder)

    return html_string


def create_html_report(
        profiles: List[fuzz_data_loader.FuzzerProfile],
        project_profile: fuzz_data_loader.MergedProjectProfile,
        coverage_url: str,
        git_repo_url: str,
        basefolder: str) -> None:
    """
    Logs a complete report. This is the current main place for looking at 
    data produced by fuzz introspector.
    """
    tables = []

    # Remove existing html report.
    report_name = "fuzz_report.html"
    if os.path.isfile(report_name):
        os.remove(report_name)

    toc_list = list()
    l.info(" - Creating top section")

    # Create html file and top bits.
    # with open(report_name, "a+") as html_report:
    html_header = html_get_header()

    # Now create the body of the html. The header will be prepended later.
    html_string = ""

    # Wrap the content
    html_string += '<div class="content-section">'

    # Add the content
    html_string += html_add_header_with_link("Project overview", 1, toc_list)

    # Project meta information
    html_string += html_add_header_with_link(
        "Project information", 2, toc_list)

    # 1) Display:
    #     - The amount of functions reached by existing fuzzers
    html_string += html_add_header_with_link(
        "Reachability overview", 3, toc_list)
    tables.append("myTable%d" % (len(tables)))

    html_string += "<p class='no-top-margin'>This is the overview of reachability by the existing fuzzers in the project</p>"
    html_string += create_top_summary_info(tables, project_profile)


    #############################################
    # Table with overview of all fuzzers.
    #############################################
    l.info(" - Creating table with overview of all fuzzers")
    html_string += html_add_header_with_link("Fuzzers overview", 3, toc_list)
    tables.append("myTable%d" % (len(tables)))
    html_string += create_overview_table(tables, profiles)

    #############################################
    # Table with details about all functions in the target project.
    #############################################
    l.info(" - Creating table with information about all functions in target")
    html_string += html_add_header_with_link(
        "Project functions overview", 2, toc_list)
    tables.append("myTable%d" % (len(tables)))
    html_string += create_all_function_table(
        tables, project_profile, coverage_url, git_repo_url, basefolder)

    #############################################
    # Section with details about each fuzzer.
    # This includes calltree for each fuzzer.
    #############################################
    l.info(" - Creating section with details about each fuzzer")
    html_string += html_add_header_with_link("Fuzzer details", 1, toc_list)

    profile_idx = 0
    for profile in profiles:
        profile_idx += 1
        html_string += create_fuzzer_detailed_section(profile, toc_list, tables, profile_idx, project_profile, coverage_url, git_repo_url, basefolder)

    #############################################
    # Handle optional analyses
    #############################################
    l.info(" - Handling optional analyses")
    html_string += html_add_header_with_link(
        "Analyses and suggestions", 1, toc_list)

    # Analysis 1
    html_string += handle_analysis_1(
            toc_list,
            tables,
            project_profile,
            basefolder,
            git_repo_url,
            coverage_url)

    #############################################
    # End of optional analyses
    #############################################

    ## Wrap up the HTML generation
    # Close the content div and content_wrapper
    html_string += "</div>\n</div>\n"

    # Add PrismJs for code snippet styling
    html_string += "<script src=\"prism.js\"></script>"
    html_string += "<script src=\"clike.js\"></script>"
    html_string += "<script src=\"custom.js\"></script>"

    ###########################
    # Footer
    ###########################
    html_string += "<script>\n"

    # Create array of all table ids
    html_string += "var tableIds = ["
    counter = 0
    for tablename in tables:
        html_string += "'%s'"%(tablename)
        if counter!=len(tables)-1:
            html_string += ", "
        else:
            html_string += "];\n"
        counter += 1

    html_string += ("</script>\n")
    html_string += ("</body>\n")
    html_string += ("</html>\n")

    ###########################
    # Fix up table of contents.
    ###########################
    html_toc_string = html_get_table_of_contents(toc_list)

    # Assemble the final HTML report and write it to a file.
    html_string = html_header + html_toc_string + html_string

    # pretty print the html code:
    soup = bs(html_string, "lxml")
    prettyHTML = soup.prettify()
    with open(report_name, "a+") as html_report:
        html_report.write(prettyHTML)

    # Copy all of the styling into the directory.
    basedir = os.path.dirname(os.path.realpath(__file__))
    style_dir = os.path.join(basedir, "styling")
    for s in ["clike.js", "prism.css", "prism.js", "styles.css", "custom.js"]:
        shutil.copy(os.path.join(style_dir, s), s)
