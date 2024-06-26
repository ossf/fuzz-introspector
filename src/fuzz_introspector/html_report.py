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
import json
import typing
import random
import string

from typing import (
    Any,
    Dict,
    List,
    Optional,
    Tuple,
)

from fuzz_introspector import (analysis, constants, html_constants,
                               html_helpers, json_report, styling, utils)

from fuzz_introspector.datatypes import project_profile, fuzzer_profile

logger = logging.getLogger(name=__name__)


def create_overview_table(tables: List[str],
                          profiles: List[fuzzer_profile.FuzzerProfile]) -> str:
    """Table with an overview of all the fuzzers"""
    html_string = html_helpers.html_create_table_head(
        tables[-1], html_constants.FUZZER_OVERVIEW_TABLE_COLUMNS)
    for profile in profiles:  # create a row for each fuzzer.
        fuzzer_filename = profile.fuzzer_source_file
        html_string += html_helpers.html_table_add_row([
            profile.identifier, fuzzer_filename,
            len(profile.functions_reached_by_fuzzer),
            len(profile.functions_unreached_by_fuzzer),
            profile.max_func_call_depth,
            len(profile.file_targets), profile.total_basic_blocks,
            profile.total_cyclomatic_complexity,
            fuzzer_filename.replace(" ", "").split("/")[-1]
        ])
    html_string += ("\n</tbody></table>")
    return html_string


def create_all_function_table(
    tables: List[str],
    proj_profile: project_profile.MergedProjectProfile,
    coverage_url: str,
    basefolder: str,
    table_id: Optional[str] = None
) -> Tuple[str, List[typing.Dict[str, Any]], List[typing.Dict[str, Any]]]:
    """Table for all functions in the project. Contains many details about each
        function"""
    random_suffix = '_' + ''.join(
        random.choices(string.ascii_lowercase + string.ascii_uppercase, k=7))
    if table_id is None:
        table_id = tables[-1]

    html_string = html_helpers.html_create_table_head(
        table_id,
        html_constants.ALL_FUNCTION_TABLE_COLUMNS,
        sort_by_column=len(html_constants.ALL_FUNCTION_TABLE_COLUMNS) - 1,
        sort_order="desc")

    # an array in development to replace html generation in python.
    # this will be stored as a json object and will be used to populate
    # the table in the frontend
    table_rows_json_html = []
    table_rows_json_report = []

    for fd_k, fd in proj_profile.get_all_functions_with_source().items():
        demangled_func_name = utils.demangle_cpp_func(fd.function_name)
        hit_percentage = proj_profile.get_func_hit_percentage(fd.function_name)

        func_cov_url = proj_profile.resolve_coverage_report_link(
            coverage_url, fd.function_source_file, fd.function_linenumber,
            fd.function_name)

        if proj_profile.runtime_coverage.is_func_hit(fd.function_name):
            func_hit_at_runtime_row = "yes"
        else:
            func_hit_at_runtime_row = "no"

        func_name_row = html_helpers.wrap_link(
            func_cov_url, html_helpers.create_coded_text(demangled_func_name))

        collapsible_id = demangled_func_name + random_suffix
        if fd.hitcount > 0:
            reached_by_fuzzers_row = html_helpers.create_collapsible_element(
                str(fd.hitcount), str(fd.reached_by_fuzzers), collapsible_id)
        else:
            reached_by_fuzzers_row = "0"

        if fd.arg_count > 0:
            args_row = html_helpers.create_collapsible_element(
                str(fd.arg_count), str(fd.arg_types), collapsible_id + "2")
        else:
            args_row = "0"

        row_element = {
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
            "Accumulated cyclomatic complexity":
            fd.total_cyclomatic_complexity,
            "Undiscovered complexity": fd.new_unreached_complexity
        }
        table_rows_json_html.append(row_element)

        # Add the entry to json list.
        # Overwrite some fields to have raw text and not HTML-formatted text.
        json_copy = row_element.copy()
        json_copy['Func name'] = demangled_func_name
        json_copy['Args'] = fd.arg_types
        json_copy['ArgNames'] = fd.arg_names
        json_copy['Reached by Fuzzers'] = fd.reached_by_fuzzers
        json_copy['return_type'] = fd.return_type
        json_copy['raw-function-name'] = fd.raw_function_name
        json_copy['callsites'] = fd.callsite
        json_copy['source_line_begin'] = fd.function_linenumber
        json_copy['source_line_end'] = fd.function_line_number_end
        json_copy['is_accessible'] = fd.is_accessible
        json_copy['is_jvm_library'] = fd.is_jvm_library
        json_copy['is_enum_class'] = fd.is_enum
        table_rows_json_report.append(json_copy)

    logger.info("Assembled a total of %d entries" %
                (len(table_rows_json_report)))
    html_string += ("</table>\n")
    return html_string, table_rows_json_html, table_rows_json_report


def create_boxed_top_summary_info(
        proj_profile: project_profile.MergedProjectProfile,
        conclusions: List[html_helpers.HTMLConclusion]) -> str:
    html_string = ""

    # Functions statically reached
    html_string += html_helpers.create_percentage_graph(
        "Functions statically reachable by fuzzers",
        proj_profile.reached_func_count, proj_profile.total_functions)

    # Cyclomatic complexity reached
    html_string += html_helpers.create_percentage_graph(
        "Cyclomatic complexity statically reachable by fuzzers",
        proj_profile.reached_complexity, proj_profile.total_complexity)

    # Function code coverage
    covered_funcs = proj_profile.get_all_runtime_covered_functions()
    html_string += html_helpers.create_percentage_graph(
        "Runtime code coverage of functions", len(covered_funcs),
        proj_profile.total_functions)

    # Wrap it in a horisontal list.
    html_string = f"""<div style="display: flex; max-width: 800px">
        {html_string}
    </div>"""

    if len(covered_funcs) > proj_profile.reached_func_count:
        # Add warning
        html_string += """<span class="warning-box blue-warning">
            <p> <b>Warning:</b>
                The number of runtime covered functions are larger than the
                number of reachable functions. This means that Fuzz Introspector found
                there are more functions covered at runtime than what is considered
                reachable based on the static analysis. This is a limitation in the
                analysis as anything covered at runtime is by definition reachable by the
                fuzzers.
            <br>
                This is likely due to a limitation in the static analysis. In this case, the
                count of functions covered at runtime is the true value, which means this
                is what should be considered "achieved" by the fuzzer.
            </p>
            <p>
                Use the project functions table below to query all functions that were
                not covered at runtime.
            </p>
        </span>"""

    if not proj_profile.has_coverage_data():
        conclusions.append(
            html_helpers.HTMLConclusion(
                severity=0,
                title="No coverage data was found",
                description=html_constants.WARNING_NO_COVERAGE))
    # Add coverage conclusion
    try:
        coverage_percentage = float(
            len(covered_funcs) / float(proj_profile.total_functions) * 100.0)
    except ZeroDivisionError:
        coverage_percentage = 0.0
    if coverage_percentage > 50.0:
        sentence = f"""Fuzzers reach {"%.5s%%"%(str(coverage_percentage))} code coverage."""
        conclusions.append(
            html_helpers.HTMLConclusion(severity=8,
                                        title=sentence,
                                        description=""))

    # Add conclusios about reachability.
    # Avoid Python due to limitations in the callgraph extraction.
    if proj_profile.target_lang != "python":
        create_reachability_conclusions(
            conclusions, proj_profile.reached_func_percentage,
            proj_profile.reached_complexity_percentage)
    return html_string


def create_reachability_conclusions(
        conclusions: List[html_helpers.HTMLConclusion],
        reached_percentage: float,
        reached_complexity_percentage: float) -> None:
    # Functions reachability
    sentence = f"""Fuzzers reach { "%.5s%%"%(str(reached_percentage)) } of all functions. """
    conclusions.append(
        html_helpers.HTMLConclusion(severity=int(reached_percentage * 0.1),
                                    title=sentence,
                                    description=""))

    # Complexity reachability
    percentage_str = "%.5s%%" % str(reached_complexity_percentage)
    sentence = f"Fuzzers reach { percentage_str } of cyclomatic complexity. "
    conclusions.append(
        html_helpers.HTMLConclusion(severity=int(reached_percentage * 0.1),
                                    title=sentence,
                                    description=""))


def create_fuzzer_profile_runtime_coverage_section(proj_profile, profile,
                                                   table_of_contents,
                                                   profile_idx,
                                                   fuzzer_table_data,
                                                   extract_conclusion,
                                                   conclusions, tables) -> str:
    html_string = ""
    # Table with all functions hit by this fuzzer
    html_string += html_helpers.html_add_header_with_link(
        "Runtime coverage analysis",
        html_helpers.HTML_HEADING.H3,
        table_of_contents,
        link=f"functions_cov_hit_{profile_idx}")
    table_name = f"myTable{len(tables)}"

    # Add this table name to fuzzer_table_data
    fuzzer_table_data[table_name] = []

    tables.append(table_name)
    func_hit_table_string = ""
    func_hit_table_string += html_helpers.html_create_table_head(
        tables[-1], [("Function name", ""), ("source code lines", ""),
                     ("source lines hit", ""), ("percentage hit", "")], 1,
        "desc")

    total_hit_functions = 0
    if profile.coverage is not None:
        for funcname in profile.coverage.covmap:
            (total_func_lines, hit_lines,
             hit_percentage) = profile.get_cov_metrics(funcname)

            if hit_percentage is not None:
                if (hit_lines and hit_lines > 0):
                    total_hit_functions += 1
                fuzzer_table_data[table_name].append({
                    "Function name":
                    funcname,
                    "source code lines":
                    total_func_lines,
                    "source lines hit":
                    hit_lines,
                    "percentage hit":
                    "%.5s" % (str(hit_percentage)) + "%"
                })
            else:
                logger.error("Could not write coverage line for function %s" %
                             funcname)
    func_hit_table_string += "</table>"

    # Get how many functions are covered relative to reachability
    uncovered_reachable_funcs = len(
        profile.get_cov_uncovered_reachable_funcs())
    reachable_funcs = len(profile.functions_reached_by_fuzzer)
    reached_funcs = reachable_funcs - uncovered_reachable_funcs
    try:
        cov_reach_proportion = (float(reached_funcs) /
                                float(reachable_funcs)) * 100.0
    except Exception:
        logger.info("reachable funcs is 0")
        cov_reach_proportion = 0.0
    str_percentage = "%.5s%%" % str(cov_reach_proportion)
    json_report.add_fuzzer_key_value_to_report(
        profile.identifier, "coverage-blocker-stats", {
            "reachable-funcs": reachable_funcs,
            "reached-funcs": reached_funcs,
            "cov-reach-proportion": cov_reach_proportion,
        })
    if extract_conclusion:
        if cov_reach_proportion < 30.0:
            conclusions.append(
                html_helpers.HTMLConclusion(
                    2, f"Fuzzer { profile.identifier } is blocked:",
                    (f"The runtime code coverage of { profile.identifier } "
                     f"covers { str_percentage } of its statically reachable code. "
                     f"This means there is some place that blocks the fuzzer "
                     f"to continue exploring more code at run time. ")))

    html_string += "<div style=\"display: flex; margin-bottom: 10px;\">"
    html_string += html_helpers.get_simple_box("Covered functions",
                                               str(total_hit_functions))
    html_string += html_helpers.get_simple_box(
        "Functions that are reachable but not covered",
        str(uncovered_reachable_funcs))

    html_string += html_helpers.get_simple_box("Reachable functions",
                                               str(reachable_funcs))
    html_string += html_helpers.get_simple_box(
        "Percentage of reachable functions covered",
        "%s%%" % str(round(cov_reach_proportion, 2)))
    html_string += "</div>"
    html_string += html_constants.INFO_SUM_OF_COVERED_FUNCS_EQ_REACHABLE_FUNCS

    if total_hit_functions > reachable_funcs:
        html_string += html_constants.WARNING_TOTAL_FUNC_OVER_REACHABLE_FUNC

    html_string += func_hit_table_string
    return html_string


def create_fuzzer_detailed_section(
        proj_profile: project_profile.MergedProjectProfile,
        profile: fuzzer_profile.FuzzerProfile,
        table_of_contents: html_helpers.HtmlTableOfContents, tables: List[str],
        profile_idx: int, conclusions: List[html_helpers.HTMLConclusion],
        extract_conclusion: bool, fuzzer_table_data: Dict[str, Any],
        dump_files: bool) -> str:
    html_string = ""
    html_string += html_helpers.html_add_header_with_link(
        f"Fuzzer: {profile.identifier}", html_helpers.HTML_HEADING.H2,
        table_of_contents)

    # Calltree fixed-width image
    html_string += html_helpers.html_add_header_with_link(
        "Call tree",
        html_helpers.HTML_HEADING.H3,
        table_of_contents,
        link=f"call_tree_{profile_idx}")

    from fuzz_introspector.analyses import calltree_analysis as cta
    calltree_analysis = cta.FuzzCalltreeAnalysis()
    calltree_analysis.dump_files = dump_files
    calltree_file_name = calltree_analysis.create_calltree(profile)

    html_string += "<p class='no-top-margin'>"
    html_string += html_constants.INFO_CALLTREE_DESCRIPTION
    html_string += html_constants.INFO_CALLTREE_LINK_BUTTON.format(
        calltree_file_name)

    html_string += ("<p class='no-top-margin'>"
                    "Call tree overview bitmap:"
                    "</p>")

    colormap_file_prefix = profile.identifier
    if "/" in colormap_file_prefix:
        colormap_file_prefix = colormap_file_prefix.replace("/", "_")
    image_name = f"{colormap_file_prefix}_colormap.png"

    color_list = html_helpers.create_horisontal_calltree_image(
        image_name, profile, dump_files)
    html_string += f"<img class=\"colormap\" src=\"{image_name}\">"

    # At this point we want to ensure there is coverage in order to proceed.
    # If there is no code coverage then the remaining will be quite bloat
    # in that it's all dependent on code coverage. As such we exit early
    # if there is none.
    if not proj_profile.has_coverage_data():
        html_string += (
            "<p>The project has no code coverage. Will not display blockers "
            "as blockers depend on code coverage.</p>")
        return html_string

    # Show the distribution of colors in the calltree.
    html_string += html_helpers.create_calltree_color_distribution_table(
        color_list)

    # Create fuzz blocker section
    html_string += create_fuzzer_profile_section_blocker_table(
        profile, profile_idx, tables, calltree_file_name, table_of_contents,
        calltree_analysis)

    profile.write_stats_to_summary_file()

    # Runtime code coverage section
    html_string += create_fuzzer_profile_runtime_coverage_section(
        proj_profile, profile, table_of_contents, profile_idx,
        fuzzer_table_data, extract_conclusion, conclusions, tables)

    # Section about files hit by fuzzers.
    html_string += create_fuzzer_profile_section_files_hit(
        profile, profile_idx, table_of_contents, tables)

    return html_string


def create_fuzzer_profile_section_blocker_table(profile, profile_idx, tables,
                                                calltree_file_name,
                                                table_of_contents,
                                                calltree_analysis):
    # Decide what kind of blockers to report: if branch blockers are not present,
    # fall back to calltree-based blockers.
    html_string = ""
    if profile.branch_blockers:
        # Populate branch blocker table
        html_fuzz_blocker_table = calltree_analysis.create_branch_blocker_table(
            profile, tables, calltree_file_name, 12)
    else:
        # Fuzz blocker table based on calltree
        html_fuzz_blocker_table = calltree_analysis.create_fuzz_blocker_table(
            profile, tables, calltree_file_name, file_link=calltree_file_name)
    if html_fuzz_blocker_table is not None:
        html_string += html_helpers.html_add_header_with_link(
            "Fuzz blockers",
            html_helpers.HTML_HEADING.H3,
            table_of_contents,
            link=f"fuzz_blocker{profile_idx}")
        html_string += html_fuzz_blocker_table
    return html_string


def create_fuzzer_profile_section_files_hit(profile, profile_idx,
                                            table_of_contents, tables):
    html_string = ""
    # Table showing which files this fuzzer hits.
    html_string += html_helpers.html_add_header_with_link(
        "Files reached",
        html_helpers.HTML_HEADING.H3,
        table_of_contents,
        link=f"files_hit_{profile_idx}")
    tables.append(f"myTable{len(tables)}")
    html_string += html_helpers.html_create_table_head(tables[-1],
                                                       [("filename", ""),
                                                        ("functions hit", "")])
    for file_target, functions_hit_in_file in profile.file_targets.items():
        html_string += html_helpers.html_table_add_row(
            [file_target, len(functions_hit_in_file)])
    html_string += "</table>\n"
    return html_string


def create_html_footer(tables):
    """Create an array of table ids wrapped in a <script> tag, and close
    <body> and <html> tags.
    """
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
    return html_footer


def write_content_to_html_files(html_full_doc, all_functions_json_html,
                                fuzzer_table_data):
    """Writes the content of the HTML static website to the relevant files.

    :param html_full_doc: content of the main fuzz_report.html file

    :param all_functions_json_html: dictionary in json format for all functions
      in the all functions table. These will be written ot a javascript file
      that is then loaded dynamically in the browser to reduce overhead of
      loading it all by way of hte .html file.

    :param fuzzer_table_data: data for tables for each fuzzer, in the detailed
      fuzzer section. To be written in a javascript file that is loaded
      dynamically.
    """
    # Dump the HTML report.
    with open(constants.HTML_REPORT, 'w') as report_file:
        report_file.write(html_helpers.prettify_html(html_full_doc))

    # Dump function data to the relevant javascript file.
    with open(constants.ALL_FUNCTION_JS, 'w') as all_function_file:
        all_function_file.write("var all_functions_table_data = ")
        all_function_file.write(json.dumps(all_functions_json_html))

    # Dump table data to relevant javascript file.
    with open(constants.FUZZER_TABLE_JS, 'w') as js_file_fd:
        js_file_fd.write("var fuzzer_table_data = ")
        js_file_fd.write(json.dumps(fuzzer_table_data))

    # Copy all of the styling into the directory.
    styling.copy_style_files(os.getcwd())


def create_section_fuzzers_overview(table_of_contents, tables,
                                    profiles) -> str:
    """Section with table with overview of all fuzzers."""
    logger.info(" - Creating table with overview of all fuzzers")
    html_report_core = "<div class=\"report-box\">"
    html_report_core += html_helpers.html_add_header_with_link(
        "Fuzzers overview", html_helpers.HTML_HEADING.H1, table_of_contents)
    html_report_core += "<div class=\"collapsible\">"
    tables.append(f"myTable{len(tables)}")
    html_report_core += create_overview_table(tables, profiles)

    # report-box
    html_report_core += "</div>"  # .collapsible
    html_report_core += "</div>"  # .report-box
    return html_report_core


def create_section_project_overview(table_of_contents, proj_profile,
                                    conclusions, report_name):
    html_overview = "<div class=\"report-box\">"
    html_overview += html_helpers.html_get_report_creation_tag()
    html_overview += html_helpers.html_add_header_with_link(
        f"Project overview: {report_name}",
        html_helpers.HTML_HEADING.H1,
        table_of_contents,
        link="Project-overview")
    html_overview += "<div class=\"collapsible\">"

    #############################################
    # Section with high level suggestions
    #############################################
    html_report_top = html_helpers.html_add_header_with_link(
        "High level conclusions", html_helpers.HTML_HEADING.H2,
        table_of_contents)

    #############################################
    # Reachability overview
    #############################################
    logger.info(" - Creating reachability overview table")
    html_report_core = html_helpers.html_add_header_with_link(
        "Reachability and coverage overview", html_helpers.HTML_HEADING.H2,
        table_of_contents)
    top_summary = create_boxed_top_summary_info(proj_profile, conclusions)
    html_report_core += top_summary

    # Close the section
    html_report_core += "</div>"  # .collapsible
    html_report_core += "</div>"  # report-box
    return html_overview, html_report_top, html_report_core


def create_section_fuzzer_detailed_section(table_of_contents, profiles,
                                           proj_profile, tables, conclusions,
                                           fuzzer_table_data, dump_files):
    """Section with details about each fuzzer, including calltree."""
    logger.info(" - Creating section with details about each fuzzer")
    html_report_core = "<div class=\"report-box\">"
    html_report_core += html_helpers.html_add_header_with_link(
        "Fuzzer details", html_helpers.HTML_HEADING.H1, table_of_contents)

    html_report_core += "<div class=\"collapsible\">"
    for profile_idx in range(len(profiles)):
        html_report_core += create_fuzzer_detailed_section(
            proj_profile, profiles[profile_idx], table_of_contents, tables,
            profile_idx, conclusions, True, fuzzer_table_data, dump_files)
    html_report_core += "</div>"  # .collapsible
    html_report_core += "</div>"  # report box
    return html_report_core


def create_section_all_functions(table_of_contents, tables, proj_profile,
                                 coverage_url, basefolder):
    """Table with details about all functions in the target project."""
    logger.info(
        " - Creating table with information about all functions in target")
    html_report_core = "<div class=\"report-box\">"
    html_report_core += html_helpers.html_add_header_with_link(
        "Project functions overview", html_helpers.HTML_HEADING.H1,
        table_of_contents)
    html_report_core += "<div class=\"collapsible\">"
    html_report_core += html_constants.INFO_ALL_FUNCTION_OVERVIEW_TEXT

    table_id = "fuzzers_overview_table"
    tables.append(table_id)
    (all_function_table, all_functions_json_html,
     all_functions_json_report) = create_all_function_table(
         tables, proj_profile, coverage_url, basefolder, table_id)
    html_report_core += all_function_table
    html_report_core += "</div>"  # .collapsible
    html_report_core += "</div>"  # report box

    return all_function_table, all_functions_json_html, all_functions_json_report, html_report_core


def create_section_optional_analyses(table_of_contents, analyses_to_run,
                                     output_json, tables, proj_profile,
                                     profiles, basefolder, coverage_url,
                                     conclusions, dump_files) -> str:
    """Creates the HTML sections containing optional analyses."""
    html_report_core = ""
    logger.info(" - Handling optional analyses")
    html_report_core += "<div class=\"report-box\">"
    html_report_core += html_helpers.html_add_header_with_link(
        "Analyses and suggestions", html_helpers.HTML_HEADING.H1,
        table_of_contents)
    html_report_core += "<div class=\"collapsible\">"

    # Combine and distinguish analyser requires output in html or both (html and json)
    combined_analyses = analyses_to_run + [
        x for x in output_json if x not in analyses_to_run
    ]
    for analysis_interface in analysis.get_all_analyses():
        analysis_name = analysis_interface.get_name()
        if analysis_name in combined_analyses:
            analysis_instance = analysis.instantiate_analysis_interface(
                analysis_interface)
            analysis_instance.dump_files = dump_files

            # Set display_html flag for the analysis_instance
            analysis_instance.set_display_html(
                analysis_name in analyses_to_run)

            html_string = analysis_instance.analysis_func(
                table_of_contents, tables, proj_profile, profiles, basefolder,
                coverage_url, conclusions)

            # Only add the HTML content if it's an analysis that we want
            # the non-json output from.
            if analysis_name in analyses_to_run:
                html_report_core += html_string
    html_report_core += "</div>"  # .collapsible
    html_report_core += "</div>"  # report box
    return html_report_core


def get_body_script_tags() -> str:
    """Add relevant <script> tag at the end of the body."""
    html_script_tags = ""
    js_files = styling.MAIN_JS_FILES
    js_files.append(constants.ALL_FUNCTION_JS)
    js_files.append(constants.OPTIMAL_TARGETS_ALL_FUNCTIONS)
    js_files.append(constants.FUZZER_TABLE_JS)
    js_files.extend(styling.JAVASCRIPT_REMOTE_SCRIPTS)
    for js_file in js_files:
        html_script_tags += f"<script src=\"{js_file}\"></script>"
    return html_script_tags


def create_html_report(introspection_proj: analysis.IntrospectionProject,
                       analyses_to_run, output_json, report_name,
                       dump_files) -> None:
    """
    Logs a complete report. This is the current main place for looking at
    data produced by fuzz introspector.
    This method will return a dict contains analyser name to instance
    mapping that requires separate json report generation to avoid
    reruning those analysing process.
    """
    profiles = introspection_proj.profiles
    proj_profile = introspection_proj.proj_profile
    coverage_url = introspection_proj.proj_profile.coverage_url
    basefolder = introspection_proj.proj_profile.basefolder

    # Main logic
    tables: List[str] = list()
    table_of_contents: html_helpers.HtmlTableOfContents = html_helpers.HtmlTableOfContents(
    )
    conclusions: List[html_helpers.HTMLConclusion] = []

    logger.info(" - Creating HTML report")

    # Create html header, which will be used to assemble the doc at the
    # end of this function.
    html_header = html_helpers.html_get_header()

    # Create a wrapper <div> of all content
    html_content_start = "<div class='content-wrapper report-page'>"

    # Start the contents section.
    html_body_start = '<div class="content-section">'

    # Create overview section
    (html_overview, html_report_top,
     html_report_core) = create_section_project_overview(
         table_of_contents, proj_profile, conclusions, report_name)

    # Create section with overview of all fuzzers
    html_report_core += create_section_fuzzers_overview(
        table_of_contents, tables, profiles)

    # Create section with table of all functions in project.
    (all_function_table, all_functions_json_html, all_functions_json_report,
     html_all_function_section) = create_section_all_functions(
         table_of_contents, tables, proj_profile, coverage_url, basefolder)
    html_report_core += html_all_function_section

    # Section with details of each fuzzer.
    fuzzer_table_data: Dict[str, Any] = dict()
    html_report_core += create_section_fuzzer_detailed_section(
        table_of_contents, profiles, proj_profile, tables, conclusions,
        fuzzer_table_data, dump_files)

    # Generate sections for all optional analyses
    html_report_core += create_section_optional_analyses(
        table_of_contents, analyses_to_run, output_json, tables, proj_profile,
        profiles, basefolder, coverage_url, conclusions, dump_files)

    # Create HTML showing the conclusions at the top of the report.
    html_report_top += html_helpers.create_conclusions_box(conclusions)

    # Close content-section.
    html_body_end = "</div>\n"
    html_body_end += get_body_script_tags()

    # Make table of contents. We can first do this now because it should be
    # done after assembling all entires in the table of contents.
    html_toc_string = html_helpers.html_get_table_of_contents(
        table_of_contents, coverage_url, profiles, proj_profile)

    # Close content-wrapper.
    html_content_end = "</div>"

    # Create the footer
    html_footer = create_html_footer(tables)

    # Assemble the final HTML report and write it to a file.
    html_full_doc = (html_header + html_content_start + html_toc_string +
                     html_body_start + html_overview + html_report_top +
                     html_report_core + html_body_end + html_content_end +
                     html_footer)

    # Load debug informaiton because it will be correlated to the introspector
    # functions.
    introspection_proj.load_debug_report()

    # Correlate debug info to introspector functions
    analysis.correlate_introspection_functions_to_debug_info(
        all_functions_json_report, introspection_proj.debug_all_functions,
        proj_profile.target_lang, introspection_proj.debug_report)

    # Write various stats and all-functions data to summary.json
    proj_profile.write_stats_to_summary_file()

    # Write all functions to all-fuzz-introspector-functions.json
    json_report.create_all_fi_functions_json(all_functions_json_report)

    # Write jvm constructor details to all-fuzz-introspector-jvm-constructor.json
    if proj_profile.target_lang == 'jvm' and all_functions_json_report:
        jvm_constructor_json_report = []
        for fd in proj_profile.all_constructors.values():
            json_copy = dict()
            json_copy['Func name'] = fd.function_name
            json_copy['func_url'] = 'N/A'
            json_copy['function_signature'] = fd.function_name
            json_copy['Functions filename'] = fd.function_source_file
            json_copy['Args'] = fd.arg_types
            json_copy['ArgNames'] = fd.arg_names
            json_copy['Function call depth'] = fd.function_depth,
            json_copy['Reached by Fuzzers'] = fd.reached_by_fuzzers
            json_copy['collapsible_id'] = fd.function_name
            json_copy['return_type'] = fd.return_type
            json_copy['raw-function-name'] = fd.raw_function_name
            json_copy['I Count'] = fd.i_count
            json_copy['BB Count'] = fd.bb_count
            json_copy['Cyclomatic complexity'] = fd.cyclomatic_complexity
            json_copy['Undiscovered complexity'] = fd.new_unreached_complexity
            json_copy['Functions reached'] = len(fd.functions_reached)
            json_copy['Reached by functions'] = len(fd.incoming_references)
            json_copy[
                'Accumulated cyclomatic complexity'] = fd.total_cyclomatic_complexity
            json_copy['callsites'] = fd.callsite
            json_copy['source_line_begin'] = fd.function_linenumber
            json_copy['source_line_end'] = fd.function_line_number_end
            json_copy['is_accessible'] = fd.is_accessible
            json_copy['is_jvm_library'] = fd.is_jvm_library
            json_copy['is_enum_class'] = fd.is_enum
            json_copy['Fuzzers runtime hit'] = 'no'
            json_copy['Func lines hit %'] = '0.0%'
            jvm_constructor_json_report.append(json_copy)

        if jvm_constructor_json_report:
            json_report.create_all_jvm_constructor_json(
                jvm_constructor_json_report)

    if dump_files:
        write_content_to_html_files(html_full_doc, all_functions_json_html,
                                    fuzzer_table_data)

        introspection_proj.dump_debug_report()

    # Copy source file for all target functions (Java project only)
    if introspection_proj.language == 'jvm':
        source_file_list = [
            func_item['Functions filename']
            for func_item in (all_functions_json_report +
                              jvm_constructor_json_report)
        ]
        utils.copy_java_source_files(source_file_list)
