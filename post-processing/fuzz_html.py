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

import fuzz_analysis
import fuzz_utils

# For pretty printing the html code:
from bs4 import BeautifulSoup as bs
import lxml.html as lh

import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle

l = logging.getLogger(name=__name__)

def create_horisontal_calltree_image(image_name, color_list):
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

def normalise_str(s1):
    return s1.replace("\t", "").replace("\r", "").replace("\n", "").replace(" ", "")

def create_table_head(table_head, items):
    html_str = f"<table id='{table_head}' class='cell-border compact stripe'><thead><tr>\n"
    #html_str = ""
    for elem in items:
        html_str += f"<th>{elem}</th>\n"
    html_str += "</tr></thead><tbody>"
    return html_str

def html_table_add_row(elems):
    html_str = "<tr>\n"
    for elem in elems:
        html_str += f"<td>{elem}</td>\n"
    html_str += "</tr>\n"
    return html_str

def html_get_header():
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

def html_get_navbar():
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

def html_get_table_of_contents(toc_list):
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


def html_add_header_with_link(header_title, title_type, toc_list, link=None):
    if link == None:
        link = header_title.replace(" ", "-")
    toc_list.append((header_title, link, title_type-1))
    html_string = f"<a id=\"{link}\">"
    html_string += f"<h{title_type}>{header_title}</h{title_type}>\n"
    return html_string


def create_overview_table(tables, profiles):
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


def create_all_function_table(tables, project_profile, coverage_url, git_repo_url, basefolder):
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

    for fd in project_profile.all_functions:
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


def create_top_summary_info(tables, project_profile):
    html_string = ""
    total_unreached_functions = set()
    total_reached_functions = set()

    for fd in project_profile.all_functions:
        if fd.hitcount == 0:
            total_unreached_functions.add(fd.function_name)
        else:
            total_reached_functions.add(fd.function_name)

    # Get the total amount of compleixty reached
    total_complexity_reached = project_profile.get_total_reached_function_count()
    total_complexity_unreached = project_profile.get_total_unreached_function_count()

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


def overlay_caltree_with_coverage(profile, project_profile, coverage_url, git_repo_url, basefolder, image_name):
    # We use the callstack to keep track of all function parents. We need this
    # when looking up if a callsite was hit or not. This is because the coverage
    # information about a callsite is located in coverage data of the function
    # in which the callsite is placed.
    callstack = dict()
    def callstack_get_parent(n, c):
        return c[int(n['depth'])-1]

    def callstack_has_parent(n, c):
        return int(n['depth'])-1 in c

    def callstack_set_curr_node(n, name, c):
        c[int(node['depth'])] = name

    is_first = True
    ct_idx = 0
    for node in profile.function_call_depths:
        node['cov-ct-idx'] = ct_idx
        ct_idx += 1

        demangled_name = fuzz_utils.demangle_cpp_func(node['function_name'])

        # Add to callstack
        callstack_set_curr_node(node, demangled_name, callstack)

        # Get hitcount for this node
        node_hitcount = 0
        if is_first:
            # The first node is always the entry of LLVMFuzzerTestOneInput
            # LLVMFuzzerTestOneInput will never have a parent in the calltree. As such, we 
            # check here if the function has been hit, and if so, make it green. We avoid
            # hardcoding LLVMFuzzerTestOneInput to be green because some fuzzers may not
            # have a single seed, and in this specific case LLVMFuzzerTestOneInput
            # will be red.
            if not demangled_name == "LLVMFuzzerTestOneInput":
                l.error("LLVMFuzzerTestOneInput must be the first node in the calltree")
                exit(1)
            coverage_data = profile.get_function_coverage("LLVMFuzzerTestOneInput")
            if len(coverage_data) == 0:
                l.error("There is no coverage data (not even all negative). Exiting")
                exit(0)

            node_hitcount = 0
            for (n_line_number, hit_count_cov) in coverage_data:
                node_hitcount = max(hit_count_cov, node_hitcount)
            is_first = False
        elif  callstack_has_parent(node, callstack):
            # Find the parent function and check coverage of the node
            coverage_data = profile.get_function_coverage(normalise_str(callstack_get_parent(node, callstack)), True)
            for (n_line_number, hit_count_cov) in coverage_data:
                if n_line_number == node['linenumber'] and hit_count_cov > 0:
                    node_hitcount = hit_count_cov
        else:
            l.error("A node should either be the first or it must have a parent")
            exit(1)
        node['cov-hitcount'] = node_hitcount

        # Map hitcount to color of target.
        def get_hit_count_color(hit_count):
            color_schemes = [ (0,1,"red"), (1, 10, "gold"), (10, 30, "yellow"),
                    (30, 50, "greenyellow"), (50, 1000000, "lawngreen") ]
            for cmin, cmax, cname in color_schemes:
                if hit_count >= cmin and hit_count < cmax:
                    return cname
            return "red"
        color_to_be = get_hit_count_color(node['cov-hitcount'])
        node['cov-color'] = color_to_be


        # Get URL to coverage report for the node.
        link = "#"
        for fd in project_profile.all_functions:
            if fd.function_name == node['function_name']:
                link = coverage_url + \
                    "%s.html#L%d" % (
                        fd.function_source_file, fd.function_linenumber)
                break
        node['cov-link'] = link

        # Find the parent
        callsite_link = "#"
        if callstack_has_parent(node, callstack):
            parent_fname = callstack_get_parent(node, callstack)
            for fd in project_profile.all_functions:
                if fuzz_utils.demangle_cpp_func(fd.function_name) == parent_fname:
                    callsite_link = coverage_url + "%s.html#L%d" % (
                            fd.function_source_file,   # parent source file
                            node['linenumber'])        # callsite line number
        node['cov-callsite-link'] = callsite_link

        # Get the Github URL to the node. However, if we got a "/" basefolder it means
        # it is a wrong basefolder and we handle this by removing the two first folders
        # in the complete path (which shuold be in most cases /src/NAME where NAME
        # is the project folder.
        if basefolder == "/":
            fd_github_url = "%s/%s#L%d" % (git_repo_url, "/".join(
                fd.function_source_file.split("/")[3:]), fd.function_linenumbe)
        else:
            fd_github_url = "%s/%s#L%d" % (git_repo_url, fd.function_source_file.replace(
                basefolder, ""), fd.function_linenumber)
        node['cov-github-url'] = fd_github_url

    # Extract data about which nodes unlocks data
    for idx1 in range(len(profile.function_call_depths)):
        n1 = profile.function_call_depths[idx1]

        # Read forward untill we see a green node. Depth must be the same or higher
        idx2 = idx1+1
        forward_red = 0
        while idx2 < len(profile.function_call_depths):
            # Check if we should break or increment forward_red
            n2 = profile.function_call_depths[idx2]
            if n2['depth'] > n1['depth']:
                break
            if n2['cov-hitcount'] != 0:
                break
            forward_red += 1
            idx2 += 1
        n1['cov-forward-reds'] = forward_red

def create_calltree(profile, project_profile, coverage_url, git_repo_url, basefolder, image_name, tables):
    """
    Creates the HTML of the calltree. Returns the HTML as a string.
    """

    # Overlay statically extracted calltree with runtime coverage information
    overlay_caltree_with_coverage(profile, project_profile, coverage_url, git_repo_url, basefolder, image_name)
 
    # Highlight the ten most useful places
    nodes_sorted_by_red_ahead = list(reversed(list(sorted(profile.function_call_depths, key=lambda x:x['cov-forward-reds']))))
    max_idx = 10
    html_string = create_table_head(tables[-1], ['Block count', 'Caltree index', 'Function', 'Callsite'])
    for node in nodes_sorted_by_red_ahead:
        print("Function block count: %d ## Function: %s ## Callsite: %s"%(node['cov-forward-reds'], node['function_name'], node['cov-callsite-link']))
        html_string += html_table_add_row([str(node['cov-forward-reds']), str(node['cov-ct-idx']), node['function_name'], "<a href=%s>call site</a>"%(node['cov-callsite-link'])])
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
        html_string += "%s <div style='margin-left: %spx' class=\"%s-background\">"%(ct_idx_str, str(indentation), color_to_be)
        html_string += "<span class=\"coverage-line-inner\">%d <code class=\"language-clike\">%s</code>"%(int(node['depth']), demangled_name)
        if node['functionSourceFile'].replace(" ","") == "/":
            func_href = ""
        else:
            func_href = "<a href=\"%s\">[function]</a>"%(link)
        html_string += "<span class=\"coverage-line-filename\">%s<a href=\"%s\">[call site]</a><span></span></div>\n"%(func_href, callsite_link)
    html_string += "</div>"

    # Create fixed-width color sequence image
    color_sequence = []
    for node in profile.function_call_depths:
        color_sequence.append(node['cov-color'])
    create_horisontal_calltree_image(image_name, color_sequence)
    return html_string

def create_fuzzer_detailed_section(profile, toc_list, tables, curr_tt_profile, project_profile, coverage_url, git_repo_url, basefolder):
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

def create_html_report(profiles,
                       project_profile,
                       coverage_url,
                       git_repo_url,
                       basefolder):
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
    #html_string += "<div class='section-wrapper'>"
    html_string += "<p class='no-top-margin'>This is the overview of reachability by the existing fuzzers in the project</p>"
    html_string += create_top_summary_info(tables, project_profile)
    #html_string += "</div>"

    l.info(" - Identifying optimal targets")
    fuzz_targets_2, new_profile_2, opt_2 = fuzz_analysis.analysis_synthesize_simple_targets(
        project_profile)

    # Table overview with how reachability is if the new fuzzers are applied.
    #html_string += html_add_header_with_link(
    #    "Optimal fuzzer reachability overview", 4, toc_list)
    #html_string += "<div class='section-wrapper'>

    #html_string += "<p class='no-top-margin'>If you implement fuzzers targetting the functions listed below, then the reachability will be:</p>"
    html_string += "<p>If you implement fuzzers that target the <a href=\"#Remaining-optimal-interesting-functions\">remaining optimal functions</a> then the reachability will be:</p>"
    tables.append(f"myTable{len(tables)}")
    html_string += create_top_summary_info(tables, new_profile_2)
    #html_string += "</div>"

    #############################################
    # Table with overview of all fuzzers.
    #############################################
    l.info(" - Creating table with overview of all fuzzers")
    html_string += html_add_header_with_link("Fuzzers overview", 3, toc_list)
    #html_string += "<div class='section-wrapper'>"
    tables.append("myTable%d" % (len(tables)))
    html_string += create_overview_table(tables, profiles)
    #html_string += "</div>"

    #############################################
    # Table with details about all functions in the target project.
    #############################################
    l.info(" - Creating table with information about all functions in target")
    html_string += html_add_header_with_link(
        "Project functions overview", 2, toc_list)
    #html_string += "<div class='section-wrapper'>"
    tables.append("myTable%d" % (len(tables)))
    html_string += create_all_function_table(
        tables, project_profile, coverage_url, git_repo_url, basefolder)
    #html_string += "</div>"

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
    # Details about the suggestions for additions to the fuzzer infra
    #############################################
    l.info(" - Creating remaining bits")
    html_string += html_add_header_with_link(
        "Analysis and suggestions", 1, toc_list)
    html_string += html_add_header_with_link(
        "Target function analysis", 2, toc_list)

    #optimal_targets, optimal_set = fuzz_analysis.analysis_get_optimal_targets(
    #    project_profile)
    #html_string += html_add_header_with_link(
    #    "All interesting functions", 3, toc_list)
    ##html_string += "<div class='section-wrapper'>"
    #html_string += "<p class='no-top-margin'>Together, the following functions will target %d number of functions</p>" % (
    #    len(optimal_set))
    #tables.append("myTable%d" % (len(tables)))
    #html_string += create_table_head(tables[-1],
    #                                 ["Func name", "Functions filename", "Arg count", "Args", "Function depth", "hitcount", "instr count", "bb count", "cyclomatic complexity", "Reachable functions", "Incoming references", "total cyclomatic complexity", "Unreached complexity"])

    #for fd in optimal_targets:
    #    html_string += html_table_add_row([
    #        "<code class='language-clike'>%s</code>" % demangle_cpp_func(
    #            fd['functionName']),
    #        fd['functionSourceFile'],
    #        fd['argCount'],
    #        fd['argTypes'],
    #        fd['functionDepth'],
    #        fd['hitcount'],
    #        fd['ICount'],
    #        fd['BBCount'],
    #        fd['CyclomaticComplexity'],
    #        len(fd['functionsReached']),
    #        len(fd['incoming_references']),
    #        fd['total_cyclomatic_complexity'],
    #        fd['new_unreached_complexity']])
    #html_string += ("</table>\n")
    #html_string += "</div>" # Close section-wrapper

    # Another way of finding optimal functions
    # We already called fuzz_analysis.analysis_synthesize_simple_targets so it would be nice not having
    # to do it again.
    #fuzz_targets, new_profile, opt_func_3 = fuzz_analysis.analysis_synthesize_simple_targets(
    #    project_profile)
    fuzz_targets = fuzz_targets_2
    new_profile = new_profile_2
    opt_func_3 = opt_2

    html_string += html_add_header_with_link(
        "Remaining optimal interesting functions", 3, toc_list)
    #html_string += "<div class='section-wrapper'>"
    #html_string += "<p class='no-top-margin'>Together, the following functions will target %d functions</p>" % (
    #    len(optimal_set))
    tables.append("myTable%d" % (len(tables)))
    html_string += create_table_head(tables[-1],
                                     ["Func name", "Functions filename", "Arg count", "Args", "Function depth", "hitcount", "instr count", "bb count", "cyclomatic complexity", "Reachable functions", "Incoming references", "total cyclomatic complexity", "Unreached complexity"])

    for fd in opt_func_3:
        if basefolder == "/":
            basefolder = "WRONG"

        if basefolder == "WRONG":
            fd_github_url = "%s/%s#L%d" % (git_repo_url, "/".join(
                fd['functionSourceFile'].split("/")[3:]), fd.function_linenumber)
        else:
            fd_github_url = "%s/%s#L%d" % (git_repo_url, fd.function_source_file.replace(
                basefolder, ""), fd.function_linenumber)

        #print("Github url: %s" % (fd_github_url))

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
    #html_string += "</div>"

    # Show fuzzer source codes
    html_string += html_add_header_with_link("New fuzzers", 2, toc_list)
    html_string += "<p>The below fuzzers are templates and suggestions for how to target the set of optimal functions above</p>"
    for filename in fuzz_targets:
        html_string += html_add_header_with_link("%s" %
                                                 (filename.split("/")[-1]), 3, toc_list)
        html_string += "<b>Target file:</b>%s<br>" % (filename)
        all_functions = ", ".join([f.function_name for f in fuzz_targets[filename]['target_fds']])
        html_string += "<b>Target functions:</b> %s" % (all_functions)
        html_string += "<pre><code class='language-clike'>%s</code></pre><br>" % (
            fuzz_targets[filename]['source_code'])

    #############################################
    # Section with information about new fuzzers
    #############################################

    # Table overview with how reachability is if the new fuzzers are applied.
    html_string += html_add_header_with_link(
        "Function reachability if adopted", 2, toc_list)
    tables.append("myTable%d" % (len(tables)))
    html_string += create_top_summary_info(tables, new_profile)

    # Details about the new fuzzers.
    html_string += html_add_header_with_link(
        "All functions overview", 3, toc_list)
    tables.append("myTable%d" % (len(tables)))
    html_string += create_all_function_table(
        tables, new_profile, coverage_url, git_repo_url, basefolder)

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
