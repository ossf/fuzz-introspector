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
"""API handlers"""

import os
import random
import json
import signal
from typing import Dict, List, Optional
import requests

from flask import Blueprint, render_template, request, redirect

from . import models, data_storage, page_texts
from .helper import function_helper

# Use these during testing.
#from app.site import test_data

blueprint = Blueprint('site', __name__, template_folder='templates')

gtag = None
is_local = False
allow_shutdown = False
local_oss_fuzz = ''

# Add functions in here to make the oracles focus on a specific API.
ALLOWED_ORACLE_RETURNS: List[str] = []

# Max length of testcase sorce code to return from API.
MAX_TEST_SIZE = 6000

# Max matches to show when searching for functions in functions view.
MAX_MATCHES_TO_DISPLAY = 180


def get_introspector_report_url_base(project_name, datestr):
    base_url = 'https://storage.googleapis.com/oss-fuzz-introspector/{0}/inspector-report/{1}/'
    project_url = base_url.format(project_name, datestr.replace("-", ""))
    return project_url


def get_introspector_report_url_source_base(project_name, datestr):
    return get_introspector_report_url_base(project_name,
                                            datestr) + "source-code"


def get_introspector_url(project_name, datestr):
    return get_introspector_report_url_base(project_name,
                                            datestr) + "fuzz_report.html"


def get_coverage_report_url(project_name, datestr, language):
    if language == 'java' or language == 'python' or language == 'go':
        file_report = "index.html"
    else:
        file_report = "report.html"
    base_url = 'https://storage.googleapis.com/oss-fuzz-coverage/{0}/reports/{1}/linux/{2}'
    project_url = base_url.format(project_name, datestr.replace("-", ""),
                                  file_report)
    return project_url


def all_functions_in_db():
    """Iterator for going through all functions in the DB"""
    for project in data_storage.get_projects():
        for function in data_storage.get_functions_by_project(project.name):
            yield function


def extract_introspector_raw_source_code(project_name, date_str,
                                         target_file) -> str:
    """Returns the contents of a source code file."""
    # Remove leading slash to avoid errors
    while target_file.startswith('/'):
        target_file = target_file[1:]

    if is_local:
        src_location = os.path.join(local_oss_fuzz, 'build', 'out',
                                    project_name, 'inspector', 'source-code',
                                    target_file)

        if not os.path.isfile(src_location):
            return ''
        with open(src_location, 'r') as f:
            return f.read()

    introspector_summary_url = os.path.join(
        get_introspector_report_url_source_base(project_name,
                                                date_str.replace("-", "")),
        target_file)

    print("URL: %s" % (introspector_summary_url))
    # Read the introspector atifact
    try:
        raw_source = requests.get(introspector_summary_url, timeout=10).text
    except:
        return ''

    return raw_source


def _light_extract_introspector_raw_source_code(project_name, date_str,
                                                target_file):
    # Remove leading slash to avoid errors
    while target_file.startswith('/'):
        target_file = target_file[1:]

    if is_local:
        src_location = os.path.join(local_oss_fuzz, 'build', 'out',
                                    project_name, 'inspector', 'light',
                                    'source_files', target_file)

        if not os.path.isfile(src_location):
            return None
        with open(src_location, 'r') as f:
            return f.read()

    introspector_url = get_introspector_report_url_base(project_name, date_str)
    source_url = introspector_url + 'light/source_files/' + target_file
    try:
        raw_source = requests.get(source_url, timeout=10).text
    except:
        return None

    return raw_source


def extract_lines_from_source_code(
        project_name,
        date_str,
        target_file,
        line_begin,
        line_end,
        print_line_numbers=False,
        sanity_check_function_end=False) -> Optional[str]:
    """Extracts source from a given file of a given date for a given Project."""

    project = get_project_with_name(project_name)
    if project is None:
        return None

    # Transform java class name to java source file path with package directories
    if project.language == 'java':
        target_file = f'/{target_file.split("$", 1)[0].replace(".", "/")}.java'

    # Light source code
    light_raw_source = _light_extract_introspector_raw_source_code(
        project_name, date_str, target_file)

    # Extract the source code from the target file
    raw_source = extract_introspector_raw_source_code(project_name, date_str,
                                                      target_file)

    if not raw_source and light_raw_source:
        raw_source = light_raw_source

    if '<Error><Code>NoSuchKey</Code><Message>The specified key does not exist.' in raw_source:
        raw_source = light_raw_source

    # Return None if source is not found.
    if raw_source is None:
        print("Did not found source")
        return raw_source

    return_source = ""
    source_lines = raw_source.split("\n")

    # Process for invalid line_begin and line_end when source is found.
    if line_begin <= 0:
        # line_begin is invalid, assume starting from the first line.
        line_begin = 1
    if line_end < line_begin:
        # line_end is invalid, assume ending at the last line.
        line_end = len(source_lines)

    # Source line numbers start from 1
    line_begin -= 1

    max_length = len(str(line_end))
    function_lines = []
    for line_num in range(line_begin, line_end):
        # To avoid list out of index from invalid line_num
        if line_num >= len(source_lines) or line_num < 0:
            continue

        if print_line_numbers:
            line_num_str = " " * (max_length - len(str(line_num)))
            return_source += f"{line_num_str}{line_num}"
        return_source += source_lines[line_num] + "\n"
        function_lines.append(source_lines[line_num])

    if sanity_check_function_end:
        found_end_braces = False

        if len(function_lines) > 0:
            if '}' in function_lines[-1]:
                found_end_braces = True
        if not found_end_braces and len(function_lines) > 1:
            if '}' in function_lines[-2] and function_lines[-1].strip() == '':
                found_end_braces = True

        if not found_end_braces:
            # Check the lines after max length
            tmp_ending = ""
            for nl in range(line_end, line_end + 10):
                if nl >= len(source_lines):
                    continue
                tmp_ending += source_lines[nl] + '\n'
                if '{' in source_lines[nl]:
                    break
                if '}' in source_lines[nl]:
                    found_end_braces = True
                    break
            if found_end_braces:
                return_source += tmp_ending

    return return_source


def get_functions_of_interest(
        project_name: str) -> List[data_storage.Function]:
    """Returns functions that are publicly available sorted by cyclomatic
    complexity and code coverage."""
    all_functions = data_storage.get_functions_by_project(project_name)
    all_functions = all_functions + data_storage.get_constructors_by_project(
        project_name)

    project_functions = []
    for function in all_functions:
        # Skipping non-related jvm methods and methods from enum classes
        # is_accessible is True by default, i.e. for non jvm projects
        if (not function.is_accessible or function.is_jvm_library
                or function.is_enum_class):
            continue
        if function.project == project_name:
            if function.runtime_code_coverage < 20.0:
                project_functions.append(function)

    # Filter based on accummulated cyclomatic complexity and low coverage
    sorted_functions_of_interest = sorted(
        project_functions,
        key=lambda x:
        (-x.accummulated_cyclomatic_complexity, x.runtime_code_coverage))

    return sorted_functions_of_interest


def get_frontpage_summary_stats() -> models.DBSummary:
    """Gets a DBSummary object with stats for front page."""
    # Get total number of projects
    all_projects = data_storage.get_projects()

    # Read from DB timestamps
    latest_db_timestamp = data_storage.DB_TIMESTAMPS[-1]
    total_functions = latest_db_timestamp.function_count
    total_fuzzers = latest_db_timestamp.fuzzer_count
    total_number_of_projects = latest_db_timestamp.project_count

    language_count = {
        'c': 0,
        'python': 0,
        'c++': 0,
        'java': 0,
        'go': 0,
        'rust': 0,
        'swift': 0
    }
    for project in all_projects:
        try:
            language_count[project.language] += 1
        except KeyError:
            continue

    # wrap it in a DBSummary
    db_summary = models.DBSummary(all_projects, total_number_of_projects,
                                  total_fuzzers, total_functions,
                                  language_count)
    return db_summary


def get_project_with_name(project_name) -> Optional[models.Project]:
    """Extracts project with given project name."""
    all_projects = data_storage.get_projects()
    for project in all_projects:
        if project.name == project_name:
            return project

    # TODO: Handle the case where there is no such project.
    return None


def get_fuction_with_name(function_name,
                          project_name) -> Optional[models.Function]:
    """Gets the function with the given function name from a given project"""

    all_functions = data_storage.get_functions_by_project(project_name)
    for function in all_functions:
        if function.name == function_name:
            return function

    # TODO: Handle the case where there is no such function
    for tmp_proj in data_storage.PROJECTS:
        proj_func_list = data_storage.get_functions_by_project(tmp_proj.name)
        for function in proj_func_list:
            return function
    return None


def get_all_related_functions(primary_function) -> List[models.Function]:
    """Gets all functions across the DB that has the same name."""
    related_functions = []
    for tmp_proj in data_storage.PROJECTS:
        proj_func_list = data_storage.get_functions_by_project(tmp_proj.name)
        for function in proj_func_list:
            # Skipping non-related jvm methods
            if not function.is_accessible or function.is_jvm_library:
                continue
            if function.name == primary_function.name and function.project != primary_function.project:
                related_functions.append(function)
    return related_functions


@blueprint.route('/')
def index():
    """Renders index page"""
    db_summary = get_frontpage_summary_stats()
    db_timestamps = data_storage.DB_TIMESTAMPS
    print("Length of timestamps: %d" % (len(db_timestamps)))
    # Maximum projects
    max_proj = 0
    max_fuzzer_count = 0
    max_function_count = 0
    max_line_count = 0
    for db_timestamp in db_timestamps:
        max_proj = max(db_timestamp.project_count, max_proj)
        max_fuzzer_count = max(db_timestamp.fuzzer_count, max_fuzzer_count)
        max_function_count = max(db_timestamp.function_count,
                                 max_function_count)
        max_line_count = max(max_line_count,
                             db_timestamp.accummulated_lines_total)

    max_proj = int(max_proj * 1.2)
    max_fuzzer_count = int(max_fuzzer_count * 1.2)
    max_function_count = int(max_function_count * 1.2)
    max_line_count = int(max_line_count * 1.2)

    oss_fuzz_total_number = len(data_storage.get_build_status())
    return render_template(
        'index.html',
        gtag=gtag,
        db_summary=db_summary,
        db_timestamps=db_timestamps,
        max_proj=max_proj,
        max_fuzzer_count=max_fuzzer_count,
        max_function_count=max_function_count,
        oss_fuzz_total_number=oss_fuzz_total_number,
        max_line_count=max_line_count,
        page_main_name=page_texts.get_page_name(),
        page_main_url=page_texts.get_page_main_url(),
        page_summary=page_texts.get_page_summary(),
        page_base_title=page_texts.get_page_base_title(),
        project_type_string=page_texts.get_project_type_string())


@blueprint.route('/function-profile', methods=['GET'])
def function_profile():
    """Renders a given function."""
    func_profile = get_fuction_with_name(request.args.get('function', 'none'),
                                         request.args.get('project', 'none'))

    related_functions = get_all_related_functions(func_profile)
    return render_template('function-profile.html',
                           gtag=gtag,
                           related_functions=related_functions,
                           function_profile=func_profile,
                           page_main_name=page_texts.get_page_name(),
                           page_main_url=page_texts.get_page_main_url(),
                           page_base_title=page_texts.get_page_base_title(),
                           base_cov_url=page_texts.get_default_coverage_base())


@blueprint.route('/project-profile', methods=['GET'])
def project_profile():
    """Renders the project profile page"""

    target_project_name = request.args.get('project', 'none')

    project = get_project_with_name(target_project_name)

    if project is not None:
        # Get the build status of the project
        all_build_status = data_storage.get_build_status()
        project_build_status = None
        for build_status in all_build_status:
            if build_status.project_name == project.name:
                project_build_status = build_status
                break

        # Get statistics of the project
        project_statistics = data_storage.PROJECT_TIMESTAMPS
        real_stats = []
        datestr = None
        latest_statistics = None
        latest_coverage_report = None
        latest_fuzz_introspector_report = None
        latest_introspector_datestr = ""
        project_url = ''
        project_repo = ''
        for ps in project_statistics:
            if ps.project_name == project.name:
                real_stats.append(ps)
                datestr = ps.date
                latest_statistics = ps

                if project_build_status:
                    project_language = project_build_status.language
                else:
                    project_language = 'c++'

                latest_coverage_report = get_coverage_report_url(
                    project.name, datestr, project_language)
                if ps.introspector_data is not None:
                    if ps.introspector_url:
                        latest_fuzz_introspector_report = ps.introspector_url
                    else:
                        latest_fuzz_introspector_report = get_introspector_url(
                            project.name, datestr)
                    latest_introspector_datestr = datestr
                if ps.project_url:
                    project_url = ps.project_url
                if ps.project_repository:
                    project_repo = ps.project_repository
        if not project_url:
            project_url = f'https://github.com/google/oss-fuzz/tree/master/projects/{project.name}'

        # Get functions of interest for the project
        # Display a maximum of 10 functions of interest. Down the line, this
        # should be more carefully constructed, perhaps based on a variety of
        # heuristics.
        functions_of_interest = list()
        functions_of_interest_all = get_functions_of_interest(project.name)
        for i in range(min(10, len(functions_of_interest_all))):
            func_of_interest = functions_of_interest_all[i]
            functions_of_interest.append({
                'function_name':
                func_of_interest.name,
                'source_file':
                func_of_interest.function_filename,
                'complexity':
                func_of_interest.accummulated_cyclomatic_complexity,
                'code_coverage':
                func_of_interest.runtime_code_coverage,
                'code_coverage_url':
                func_of_interest.code_coverage_url,
            })

        return render_template(
            'project-profile.html',
            gtag=gtag,
            project=project,
            project_statistics=real_stats,
            has_project_details=True,
            has_project_stats=True,
            project_build_status=project_build_status,
            functions_of_interest=functions_of_interest,
            latest_coverage_report=None,
            latest_statistics=latest_statistics,
            latest_fuzz_introspector_report=latest_fuzz_introspector_report,
            latest_introspector_datestr=latest_introspector_datestr,
            page_base_title=page_texts.get_page_base_title(),
            project_url=project_url,
            page_main_url=page_texts.get_page_main_url(),
            page_main_name=page_texts.get_page_name(),
            base_cov_url=page_texts.get_default_coverage_base(),
            project_repo=project_repo)

    # Either this is a wrong project or we only have a build status for it
    all_build_status = data_storage.get_build_status()
    for build_status in all_build_status:
        if build_status.project_name == target_project_name:
            project = models.Project(name=build_status.project_name,
                                     language=build_status.language,
                                     date="",
                                     fuzzer_count=0,
                                     coverage_data=None,
                                     introspector_data=None,
                                     project_repository=None,
                                     light_analysis={})

            # Get statistics of the project
            project_statistics = data_storage.PROJECT_TIMESTAMPS
            real_stats = []
            datestr = None
            latest_statistics = None
            latest_coverage_report = None
            latest_fuzz_introspector_report = None
            latest_introspector_datestr = ""
            project_repo = ''
            for ps in project_statistics:
                if ps.project_name == project.name:
                    real_stats.append(ps)
                    datestr = ps.date
                    latest_statistics = ps
                    latest_coverage_report = get_coverage_report_url(
                        build_status.project_name, datestr,
                        build_status.language)
                    if ps.introspector_data is not None:
                        if ps.introspector_url:
                            latest_fuzz_introspector_report = ps.introspector_url
                        else:
                            latest_fuzz_introspector_report = get_introspector_url(
                                project.name, datestr)
                        latest_introspector_datestr = datestr
                    if ps.project_repository:
                        project_repo = ps.project_repository

            if datestr and len(real_stats) > 0:
                latest_coverage_report = get_coverage_report_url(
                    build_status.project_name, datestr, build_status.language)
            else:
                latest_coverage_report = None
            project_url = f'https://github.com/google/oss-fuzz/tree/master/projects/{project.name}'
            return render_template(
                'project-profile.html',
                gtag=gtag,
                project=project,
                project_statistics=real_stats,
                has_project_details=False,
                has_project_stats=len(real_stats) > 0,
                project_build_status=build_status,
                functions_of_interest=[],
                latest_coverage_report=latest_coverage_report,
                coverage_date=datestr,
                project_url=project_url,
                latest_statistics=latest_statistics,
                latest_introspector_datestr=latest_introspector_datestr,
                project_repo=project_repo,
                page_main_name=page_texts.get_page_name(),
                page_main_url=page_texts.get_page_main_url(),
                page_base_title=page_texts.get_page_base_title(),
                base_cov_url=page_texts.get_default_coverage_base())
    print("Nothing to do. We shuold probably have a 404")
    return redirect("/")


@blueprint.route('/function-search')
def function_search():
    """Renders function search page"""
    info_msg = None
    query = request.args.get('q', '')
    print("query: { %s }" % (query))
    if query == '':
        # Pick a random interesting query
        # Some queries involving fuzzing-interesting targets.
        interesting_query_roulette = [
            'deserialize', 'parse', 'parse_xml', 'read_file', 'read_json',
            'read_xml', 'message', 'request', 'parse_header', 'parse_request',
            'header', 'decompress', 'file_read'
        ]
        interesting_query = random.choice(interesting_query_roulette)
        tmp_list = []
        for function in all_functions_in_db():
            if interesting_query in function.name:
                tmp_list.append(function)
        functions_to_display = tmp_list

        # Shuffle to give varying results each time
        random.shuffle(functions_to_display)

        total_matches = len(functions_to_display)
        if total_matches >= 100:
            functions_to_display = functions_to_display[:100]
        info_msg = f"No query was given, picked the query \"{interesting_query}\" for this"
    else:
        tmp_list = []
        for function in all_functions_in_db():
            if query in function.name:
                tmp_list.append(function)
        functions_to_display = tmp_list

        total_matches = len(functions_to_display)
        if total_matches >= MAX_MATCHES_TO_DISPLAY:
            functions_to_display = functions_to_display[
                0:MAX_MATCHES_TO_DISPLAY]
            info_msg = f"Found {total_matches} matches. Only showing the first {MAX_MATCHES_TO_DISPLAY}."

    return render_template('function-search.html',
                           gtag=gtag,
                           all_functions=functions_to_display,
                           page_main_name=page_texts.get_page_name(),
                           page_main_url=page_texts.get_page_main_url(),
                           info_msg=info_msg,
                           page_base_title=page_texts.get_page_base_title())


@blueprint.route('/projects-overview')
def projects_overview():
    # Get statistics of the project
    project_statistics = data_storage.PROJECT_TIMESTAMPS
    latest_coverage_profiles = dict()
    for ps in project_statistics:
        latest_coverage_profiles[ps.project_name] = ps

    return render_template(
        'projects-overview.html',
        gtag=gtag,
        all_projects=latest_coverage_profiles.values(),
        projects_not_in_ossfuzz=data_storage.PROJECTS_NOT_IN_OSSFUZZ,
        page_base_title=page_texts.get_page_base_title(),
        page_main_name=page_texts.get_page_name(),
        page_main_url=page_texts.get_page_main_url(),
    )


def oracle_3(all_functions, all_projects):
    """Filters fucntions that:
    - "have far reach but low coverage and are likely easy to trigger"

    More technically, functions with:
        - a low code coevrage percent in the function itself;
        - a high accummulated cyclomatic complexity;
        - less than a certain number of arguments (3 or below);
        - at least one argument.
    """
    functions_of_interest = []
    projects_added = dict()

    for function in all_functions:
        if (function.runtime_code_coverage < 20.0
                and function.accummulated_cyclomatic_complexity > 200
                and len(function.function_argument_names) <= 3
                and len(function.function_argument_names) > 0):

            # Skip non c/c++
            to_continue = False
            for proj in all_projects:
                if proj.name == function.project and proj.language in {
                        'c', 'c++'
                }:
                    to_continue = True
            if not to_continue:
                continue

            # If there is only a single argument then we want it to be
            # something that is "fuzzable", i.e. either a string or a
            # char pointer.
            if len(function.function_arguments) == 1 and (
                    "str" not in function.function_arguments[0]
                    or "char" not in function.function_arguments):
                continue

            if function.project not in projects_added:
                projects_added[function.project] = []

            current_list = projects_added[function.project]
            if len(current_list) < 5:
                current_list.append(function)
            else:
                for idx in range(len(current_list)):
                    if current_list[
                            idx].accummulated_cyclomatic_complexity < function.accummulated_cyclomatic_complexity:
                        current_list[idx] = function
                        break

    for functions in projects_added.values():
        functions_of_interest += functions
    return functions_of_interest


def oracle_1(all_functions,
             all_projects,
             max_project_count=5,
             no_static_functions=False,
             only_referenced_functions=False):
    tmp_list = []
    project_count = dict()

    if only_referenced_functions and len(all_projects) == 1:
        xref_dict = get_cross_reference_dict_from_project(all_projects[0].name)
    else:
        xref_dict = {}

    for function in all_functions:
        interesting_fuzz_keywords = {
            'deserialize',
            'parse',
            'parse_xml',
            'read_file',
            'read_json',
            'read_xml',
            'request',
            'parse_header',
            'parse_request',
            'compress',
            'file_read',
            'read_message',
            'load_image',
        }
        if only_referenced_functions and function.name not in xref_dict:
            continue

        is_interesting_func = False
        if any(fuzz_keyword in function.name.lower()
               for fuzz_keyword in interesting_fuzz_keywords):
            is_interesting_func = True

        if any(
                fuzz_keyword.replace("_", "") in function.name.lower()
                for fuzz_keyword in interesting_fuzz_keywords):
            is_interesting_func = True

        if not is_interesting_func:
            continue

        if (function.runtime_code_coverage < 60.0
                and project_count.get(function.project, 0) < max_project_count
                and function.accummulated_cyclomatic_complexity > 30):

            to_continue = False

            for proj in all_projects:
                if proj.name == function.project and proj.language in {
                        'c', 'c++'
                }:
                    to_continue = True
            if not to_continue:
                continue

            if no_static_functions:
                # Exclude function if it's static
                if is_static(function):
                    continue
            tmp_list.append(function)
            current_count = project_count.get(function.project, 0)
            current_count += 1
            project_count[function.project] = current_count

    functions_to_display = tmp_list
    funcs_max_to_display = 4000
    total_matches = len(functions_to_display)
    if total_matches >= funcs_max_to_display:
        functions_to_display = functions_to_display[:funcs_max_to_display]

    return functions_to_display


def match_easy_fuzz_arguments(function: models.Function) -> bool:
    """Returns true if the function args are considered easy to fuzz."""
    debug_args = function.debug_data.get('args')
    if not debug_args:
        return False
    if len(debug_args
           ) == 2 and 'char *' in debug_args[0] and 'int' in debug_args[1]:
        return True

    if len(debug_args) == 1:
        if "string" in debug_args[0]:
            return True

        if "char *" in debug_args[0]:
            return True

    return False


def is_static(target_function) -> bool:
    """Returns True if a function is determined to be static and False
    otherwise, including if undecided."""

    latest_introspector_datestr = get_latest_introspector_date(
        target_function.project)
    if is_local:
        latest_introspector_datestr = "norelevant"

    if not latest_introspector_datestr:
        return False

    src_begin = target_function.source_line_begin
    src_end = target_function.source_line_end
    src_file = target_function.function_filename

    # Check if we have accompanying debug info
    debug_source_dict = target_function.debug_data.get('source', None)
    if debug_source_dict:
        source_line = int(debug_source_dict.get('source_line', -1))
        if source_line != -1:
            src_begin = source_line
    src_begin -= 2

    source_code = extract_lines_from_source_code(
        target_function.project,
        latest_introspector_datestr,
        src_file,
        src_begin,
        src_end,
        sanity_check_function_end=True)
    if source_code is None:
        return False

    # Cut off the part before the code body. This is a heuristic from looking
    # at the source, and it's bound to have some false positives. However,
    # this will do for now.
    pre_body = ''
    for line in source_code.split("\n"):
        if '{' in line:
            break
        pre_body += line + '\n'
    if 'static' in pre_body:
        return True
    return False


def remove_functions_with_header_declarations(function_list):
    """For a list of functions sorts out functions without possible header
    declarations.
    """
    new_functions = []
    for function in function_list:
        possible_header_files = function.debug_data.get(
            'possible-header-files', [])
        if not possible_header_files:
            continue
        new_functions.append(function)
    return new_functions


def oracle_2(all_functions,
             all_projects,
             no_static_functions=False,
             only_referenced_functions=False,
             only_functions_declared_in_header_files=False):
    tmp_list = []
    project_count = dict()
    funcs_max_to_display = 4000

    if len(all_projects) == 1:
        project_to_target = all_projects[0]
    else:
        project_to_target = None

    # If indicated only include functions with cross references
    if only_referenced_functions and len(all_projects) == 1:
        xref_dict = get_cross_reference_dict_from_project(all_projects[0].name)

        functions_with_xref = []
        for function in all_functions:
            if function.name in xref_dict:
                functions_with_xref.append(function)
        functions_to_analyse = functions_with_xref
    else:
        functions_to_analyse = all_functions

    if only_functions_declared_in_header_files:
        functions_to_analyse = remove_functions_with_header_declarations(
            functions_to_analyse)

    for function in functions_to_analyse:
        if project_to_target:
            if function.project != project_to_target.name:
                continue

        if not match_easy_fuzz_arguments(function):
            continue

        if function.accummulated_cyclomatic_complexity < 150:
            continue

        if no_static_functions:
            # Exclude function if it's static
            if is_static(function):
                continue

        tmp_list.append(function)
        current_count = project_count.get(function.project, 0)
        current_count += 1
        project_count[function.project] = current_count

    functions_to_display = tmp_list

    total_matches = len(functions_to_display)
    if total_matches >= funcs_max_to_display:
        functions_to_display = functions_to_display[:funcs_max_to_display]

    return functions_to_display


@blueprint.route('/target_oracle')
def target_oracle():
    all_projects = data_storage.get_projects()
    functions_to_display = []

    total_funcs = set()
    oracle_pairs = [(oracle_1, "heuristic 1"), (oracle_2, "heuristic 2"),
                    (oracle_3, "heuristic 3")]
    random.shuffle(oracle_pairs)
    funcs_max_to_display = 150
    project_list = [proj.name for proj in data_storage.PROJECTS]
    random.shuffle(project_list)
    for oracle, heuristic_name in oracle_pairs:
        for tmp_proj in project_list:
            if len(functions_to_display) > funcs_max_to_display:
                break
            proj_func_list = data_storage.get_functions_by_project(tmp_proj)
            func_targets = oracle(proj_func_list, all_projects)
            for func in func_targets:
                if func in total_funcs:
                    continue
                total_funcs.add(func)
                functions_to_display.append((func, heuristic_name))
    func_to_lang = dict()
    for func, _ in functions_to_display:
        language = 'c'
        for proj in all_projects:
            if proj.name == func.project:
                language = proj.language
                break
        # We may overwrite here, and in that case we just use the new
        # heuristic for labeling.
        func_to_lang[func.name] = language

    return render_template('target-oracle.html',
                           gtag=gtag,
                           functions_to_display=functions_to_display,
                           func_to_lang=func_to_lang,
                           page_base_title=page_texts.get_page_base_title(),
                           page_main_name=page_texts.get_page_name(),
                           page_main_url=page_texts.get_page_main_url())


@blueprint.route('/indexing-overview')
def indexing_overview():
    build_status = data_storage.get_build_status()

    languages_summarised = dict()
    for bs in build_status:
        if bs.language not in languages_summarised:
            languages_summarised[bs.language] = {
                'all': 0,
                'fuzz_build': 0,
                'cov_build': 0,
                'introspector_build': 0
            }
        languages_summarised[bs.language]['all'] += 1
        languages_summarised[bs.language][
            'fuzz_build'] += 1 if bs.fuzz_build_status == True else 0
        languages_summarised[bs.language][
            'cov_build'] += 1 if bs.coverage_build_status == True else 0
        languages_summarised[bs.language][
            'introspector_build'] += 1 if bs.introspector_build_status == True else 0

    print(json.dumps(languages_summarised))

    return render_template('indexing-overview.html',
                           gtag=gtag,
                           all_build_status=build_status,
                           languages_summarised=languages_summarised,
                           page_base_title=page_texts.get_page_base_title(),
                           page_main_name=page_texts.get_page_name(),
                           page_main_url=page_texts.get_page_main_url())


@blueprint.route('/about')
def about():
    return render_template('about.html',
                           about_content=page_texts.get_about_text(),
                           gtag=gtag,
                           page_main_name=page_texts.get_page_name(),
                           page_main_url=page_texts.get_page_main_url(),
                           page_base_title=page_texts.get_page_base_title())


@blueprint.route('/api')
def api():
    return render_template('api.html',
                           gtag=gtag,
                           page_main_name=page_texts.get_page_name(),
                           page_main_url=page_texts.get_page_main_url(),
                           page_base_title=page_texts.get_page_base_title())


@blueprint.route('/api/optimal-targets')
def api_optimal_targets():
    """Returns the list of functions generated by Fuzz Introspector's analysis
    `Optimal Targets`.
    """
    project_name = request.args.get('project', None)
    if project_name is None:
        return {'result': 'error', 'msg': 'Please provide project name'}

    only_functions_declared_in_header_files_arg = request.args.get(
        'only-with-header-file-declaration', 'false').lower()
    if only_functions_declared_in_header_files_arg == 'true':
        only_functions_declared_in_header_files = True
    else:
        only_functions_declared_in_header_files = False

    target_project = get_project_with_name(project_name)
    if target_project is None:
        return {'result': 'error', 'msg': 'Project not in the database'}

    if target_project.introspector_data is None:
        return {'result': 'error', 'msg': 'Found no introspector data.'}

    # Get all functions of the target project
    project_functions = data_storage.get_functions_by_project(project_name)

    try:
        optimal_targets_raw = target_project.introspector_data[
            'optimal_targets']
        function_model_optimal_targets = []
        for function in optimal_targets_raw:
            substituted_function = None
            for model_func in project_functions:
                if model_func.name == function['name'].replace(' ', ''):
                    if only_functions_declared_in_header_files:
                        possible_header_files = model_func.debug_data.get(
                            'possible-header-files', [])
                        if not possible_header_files:
                            continue

                    substituted_function = {
                        'function_name': model_func.name,
                        'function_filename': model_func.function_filename,
                        'runtime_coverage_percent':
                        model_func.runtime_code_coverage,
                        'accummulated_complexity':
                        model_func.accummulated_cyclomatic_complexity,
                        'function_arguments': model_func.function_arguments,
                        'function_argument_names':
                        model_func.function_argument_names,
                        'return_type': model_func.return_type,
                        'is_reached': model_func.is_reached,
                        'reached_by_fuzzers': model_func.reached_by_fuzzers,
                        'raw_function_name': model_func.raw_function_name,
                        'source_line_begin': model_func.source_line_begin,
                        'source_line_end': model_func.source_line_end,
                        'function_signature': model_func.func_signature,
                        'debug_summary': model_func.debug_data,
                    }
                    break
            if substituted_function:
                function_model_optimal_targets.append(substituted_function)

        return {
            'result': 'success',
            'functions': function_model_optimal_targets
        }
    except KeyError:
        return {'result': 'error', 'msg': 'Found no optimal analysis.'}
    except TypeError:
        return {'result': 'error', 'msg': 'Found no introspector data.'}


def _light_harness_source_and_executable(target_project):
    # Check if light analysis is there
    light_pairs_to_ret = []
    if target_project.light_analysis:
        light_pairs = target_project.light_analysis.get('all-pairs', [])
        for light_pair in light_pairs:
            ls = light_pair.get('harness_source', '')
            lh = light_pair.get('harness_executable', '')
            if '/' in lh:
                continue
            if ls and lh:
                light_pairs_to_ret.append({'source': ls, 'executable': lh})
    return light_pairs_to_ret


@blueprint.route('/api/harness-source-and-executable')
def harness_source_and_executable():
    """API that returns a pair of harness executable/source"""
    project_name = request.args.get('project', None)
    if project_name is None:
        return {'result': 'error', 'msg': 'Please provide project name'}

    target_project = get_project_with_name(project_name)
    if target_project is None:
        return {'result': 'error', 'msg': 'Project not in the database'}

    light_pairs_to_ret = _light_harness_source_and_executable(target_project)

    all_file_json = os.path.join(
        os.path.dirname(__file__),
        f"../static/assets/db/db-projects/{project_name}/all_files.json")

    if not os.path.isfile(all_file_json):
        if light_pairs_to_ret:
            return {'result': 'success', 'pairs': light_pairs_to_ret}
        return {'result': 'error', 'msg': 'Did not find file check json'}

    if target_project.introspector_data is None:
        return {'result': 'error', 'msg': 'Found no introspector data.'}

    try:
        annotated_cfg = target_project.introspector_data['annotated_cfg']
    except KeyError:
        return {'result': 'error', 'msg': 'Found no annotated CFG data.'}
    except TypeError:
        return {'result': 'error', 'msg': 'Found no introspector data.'}

    source_harness_pairs = []
    for harness_dict in annotated_cfg:
        harness_executable = harness_dict.get('fuzzer_name', '/')
        if '/' in harness_executable:
            continue
        source_harness_pairs.append({
            'source':
            harness_dict.get('source_file', ''),
            'executable':
            harness_executable
        })

    # Ensure the files are present in the soruce code
    with open(all_file_json, 'r') as f:
        all_files_list = json.loads(f.read())

    for harness_dict in source_harness_pairs:
        found_harnesses = []
        for source_file in all_files_list:
            if os.path.basename(
                    harness_dict['source']) == os.path.basename(source_file):
                found_harnesses.append(source_file)
        if len(found_harnesses) == 1:
            harness_dict['source'] = found_harnesses[0]
        else:
            print("Did not find one matching harness")
            print(str(found_harnesses))

    return {'result': 'success', 'pairs': source_harness_pairs}


@blueprint.route('/api/annotated-cfg')
def api_annotated_cfg():
    """API that returns the annotated  CFG of a project."""
    project_name = request.args.get('project', None)
    if project_name is None:
        return {'result': 'error', 'msg': 'Please provide project name'}

    target_project = get_project_with_name(project_name)
    if target_project is None:
        return {'result': 'error', 'msg': 'Project not in the database'}

    if target_project.introspector_data is None:
        return {'result': 'error', 'msg': 'Found no introspector data.'}

    try:
        return {
            'result': 'success',
            'project': {
                'name': project_name,
                'annotated_cfg':
                target_project.introspector_data['annotated_cfg'],
            }
        }
    except KeyError:
        return {'result': 'error', 'msg': 'Found no annotated CFG data.'}
    except TypeError:
        return {'result': 'error', 'msg': 'Found no introspector data.'}


@blueprint.route('/api/project-summary')
def api_project_summary():
    project_name = request.args.get('project', None)
    if project_name is None:
        return {'result': 'error', 'msg': 'Please provide project name'}
    target_project = get_project_with_name(project_name)
    if target_project is None:
        return {'result': 'error', 'msg': 'Project not in the database'}

    return {
        'result': 'success',
        'project': {
            'name': project_name,
            'runtime_coverage_data': target_project.coverage_data,
            'introspector_data': target_project.introspector_data
        }
    }


@blueprint.route('/api/branch-blockers')
def branch_blockers():
    """API that returns the branch blockers of project."""
    project_name = request.args.get('project', None)
    if project_name is None:
        return {'result': 'error', 'msg': 'Please provide project name'}

    target_project = get_project_with_name(project_name)
    if target_project is None:
        return {'result': 'error', 'msg': 'Project not in the database'}

    all_branch_blockers = data_storage.get_project_branch_blockers(
        target_project.name)

    project_blockers = []
    for blocker in all_branch_blockers:
        if blocker.project_name == project_name:
            project_blockers.append({
                'project_name':
                blocker.project_name,
                'function_name':
                blocker.function_name,
                'source_file':
                blocker.source_file,
                'src_linenumber':
                blocker.src_linenumber,
                'unique_blocked_coverage':
                blocker.unique_blocked_coverage,
                'blocked_unique_functions':
                blocker.blocked_unique_functions
            })
    return {'result': 'success', 'project_blockers': project_blockers}


def get_function_from_func_signature(func_signature, project_name):
    all_functions = data_storage.get_functions_by_project(project_name)
    all_constructors = data_storage.get_constructors_by_project(project_name)
    for function in (all_functions + all_constructors):
        if function.func_signature == func_signature:
            return function
    return None


@blueprint.route('/api/get-header-files-needed-for-function')
def get_header_files_needed_for_function():
    """Return the header files needed for a given function"""
    project_name = request.args.get('project', None)
    if project_name is None:
        return {'result': 'error', 'msg': 'Please provide a project name'}

    function_signature = request.args.get('function_signature', None)
    if function_signature is None:
        return {'result': 'error', 'msg': 'No function signature provided'}

    # Get function from function signature
    target_function = get_function_from_func_signature(function_signature,
                                                       project_name)
    if target_function is None:
        return {
            'result': 'error',
            'msg': 'Function signature could not be found'
        }
    headers_to_include = target_function.debug_data.get(
        'possible-header-files', [])
    return {'result': 'succes', 'headers-to-include': headers_to_include}


@blueprint.route('/api/all-cross-references')
def api_cross_references():
    """Returns a json representation of all the functions in a given project"""
    project_name = request.args.get('project', None)
    if project_name is None:
        return {'result': 'error', 'msg': 'Please provide a project name'}

    function_signature = request.args.get('function_signature', None)
    if function_signature is None:
        return {'result': 'error', 'msg': 'No function signature provided'}

    # Get function from function signature
    target_function = get_function_from_func_signature(function_signature,
                                                       project_name)
    if target_function is None:
        return {
            'result': 'error',
            'msg': 'Function signature could not be found'
        }
    function_name = target_function.raw_function_name

    # Get all functions of the target project
    project_functions = data_storage.get_functions_by_project(project_name)

    func_xrefs = []
    xrefs = []
    for function in project_functions:
        callsites = function.callsites
        for cs_dst in callsites:
            if cs_dst == function_name:
                func_xrefs.append(function)
                all_locations = function.callsites[cs_dst]
                for loc in all_locations:
                    filename = loc.split('#')[0]
                    cs_linenumber = int(loc.split(':')[-1])
                    xrefs.append({
                        'filename': function.function_filename,
                        'cs_linenumber': cs_linenumber,
                        'src_func': function.name,
                        'dst_func': function_name
                    })
    return {'result': 'success', 'callsites': xrefs}


@blueprint.route('/api/get-project-language-from-souce-files')
def api_get_project_language_from_source_files():
    """Gets the project language based on the file extensions of the project"""
    project_name = request.args.get('project', None)
    if project_name is None:
        return {'result': 'error', 'msg': 'Please provide a project name'}

    all_file_json = os.path.join(
        os.path.dirname(__file__),
        f"../static/assets/db/db-projects/{project_name}/all_files.json")
    if not os.path.isfile(all_file_json):
        return {'result': 'error', 'msg': 'Did not find file check json'}

    # Ensure the files are present in the soruce code
    with open(all_file_json, 'r') as f:
        all_files_list = json.loads(f.read())

    languages = {'c': 0, 'c++': 0, 'python': 0, 'java': 0}

    print("")

    for source_file in all_files_list:
        print(source_file)
        _, file_ext = os.path.splitext(source_file)
        if file_ext == '.c':
            languages['c'] += 1
        elif file_ext == '.cc' or file_ext == '.cpp' or file_ext == '.c++':
            languages['c++'] += 1
        elif file_ext == '.py':
            languages['python'] += 1
        elif file_ext == '.java':
            languages['java'] += 1

    print(json.dumps(languages, indent=2))
    max_language = ''
    max_language_count = -1
    for language, count in languages.items():
        if max_language_count <= count:
            max_language_count = count
            max_language = language
    return {'result': 'success', 'language': max_language}


@blueprint.route('/api/all-project-source-files')
def api_project_all_project_source_files():
    """Returns a json representation of all source file path in a given
    project"""
    project_name = request.args.get('project', None)
    if project_name is None:
        return {'result': 'error', 'msg': 'Please provide a project name'}

    src_path_list = []
    if is_local:
        src_json = os.path.join(local_oss_fuzz, 'build', 'out', project_name,
                                'inspector', 'source-code', 'index.json')
        if os.path.isfile(src_json):
            with open(src_json, 'r') as f:
                src_path_list = json.load(f)
    else:
        # Get statistics of the project
        date_str = None
        for ps in data_storage.PROJECT_TIMESTAMPS:
            if ps.project_name == project_name:
                if ps.introspector_data is not None:
                    date_str = ps.date

        if date_str:
            introspector_summary_url = get_introspector_report_url_source_base(
                project_name, date_str.replace("-", "")) + 'index.json'

            print("URL: %s" % (introspector_summary_url))

            # Read the introspector atifact
            try:
                src_path_str = str(
                    requests.get(introspector_summary_url, timeout=10).text)
                src_path_list = json.loads(src_path_str)
            except:
                # Ignore the error and assume no source path is found
                pass

    return {'result': 'success', 'src_path': src_path_list}


@blueprint.route('/api/all-functions')
def api_project_all_functions():
    """Returns a json representation of all the functions in a given project"""
    project_name = request.args.get('project', None)
    if project_name is None:
        return {'result': 'error', 'msg': 'Please provide a project name'}

    # Get all of the functions
    list_to_return = function_helper.filter_sort_functions(
        data_storage.get_functions_by_project(project_name), False)

    return {'result': 'success', 'functions': list_to_return}


@blueprint.route('/api/all-jvm-constructors')
def api_project_all_jvm_constructors():
    """Returns a json representation of all the constructors in a given project"""
    project_name = request.args.get('project', None)
    if project_name is None:
        return {'result': 'error', 'msg': 'Please provide a project name'}

    # Get all of the constructor
    list_to_return = function_helper.filter_sort_functions(
        data_storage.get_constructors_by_project(project_name), False)

    return {'result': 'success', 'functions': list_to_return}


@blueprint.route('/api/all-public-candidates')
def api_project_all_public_candidates():
    """
        Returns a json representation of all the functions / constructors
        candidates for further process in a given project.
    """
    project_name = request.args.get('project', None)
    if project_name is None:
        return {'result': 'error', 'msg': 'Please provide a project name'}

    target_list = data_storage.get_functions_by_project(
        project_name) + data_storage.get_constructors_by_project(project_name)

    # Get the list of function / constructor candidiates to return
    list_to_return = function_helper.filter_sort_functions(target_list, True)

    return {'result': 'success', 'functions': list_to_return}


@blueprint.route('/api/all-public-classes')
def api_project_all_public_classes():
    """
        Return a list of public classes in the project.
    """
    project_name = request.args.get('project', None)
    if project_name is None:
        return {'result': 'error', 'msg': 'Please provide a project name'}

    project = get_project_with_name(project_name)
    if not project:
        return {'result': 'error', 'msg': 'Project not found'}

    target_list = data_storage.get_functions_by_project(
        project_name) + data_storage.get_constructors_by_project(project_name)

    # Get a list of public class to return
    list_to_return = list(function_helper.get_public_class_list(target_list))

    return {'result': 'success', 'classes': list_to_return}


@blueprint.route('/api/project-source-code')
def api_project_source_code():
    """Returns a json representation of all the functions in a given project"""
    project_name = request.args.get('project', None)
    if project_name is None:
        return {'result': 'error', 'msg': 'Please provide a project name'}
    filepath = request.args.get('filepath', None)
    if filepath is None:
        return {'result': 'error', 'msg': 'No filepath provided'}

    begin_line_str = request.args.get('begin_line', None)
    if begin_line_str is None:
        return {'result': 'error', 'msg': 'No begin line provided'}

    end_line_str = request.args.get('end_line', None)
    if end_line_str is None:
        return {'result': 'error', 'msg': 'No end line provided'}

    try:
        begin_line = int(begin_line_str)
        end_line = int(end_line_str)
    except ValueError:
        return {
            'result': 'error',
            'msg': 'begin line or end line are not valid integer'
        }

    # If this is a local build do not look for project timestamps
    if is_local:
        source_code = extract_lines_from_source_code(project_name, '',
                                                     filepath, begin_line,
                                                     end_line)
        if source_code is None:
            return {'result': 'error', 'msg': 'no source code'}

        return {'result': 'success', 'source_code': source_code}

    latest_introspector_datestr = get_latest_introspector_date(project_name)
    if not latest_introspector_datestr:
        return {'result': 'error', 'msg': 'No introspector builds.'}

    source_code = extract_lines_from_source_code(project_name,
                                                 latest_introspector_datestr,
                                                 filepath, int(begin_line),
                                                 int(end_line))
    if source_code is None:
        return {'result': 'error', 'msg': 'no source code'}

    return {'result': 'success', 'source_code': source_code}


def get_latest_introspector_date(project_name: str) -> str:
    """Gets the date of the most recent successful introspector build."""
    all_build_status = data_storage.get_build_status()
    latest_introspector_datestr = ''
    for build_status in all_build_status:
        if build_status.project_name == project_name:

            # Get statistics of the project
            project_statistics = data_storage.PROJECT_TIMESTAMPS
            for ps in project_statistics:
                if ps.project_name == project_name:
                    datestr = ps.date
                    if ps.introspector_data is not None:
                        latest_introspector_datestr = datestr
    return latest_introspector_datestr


@blueprint.route('/api/project-test-code')
def api_project_test_code():
    """Extracts source code of a test"""
    project_name = request.args.get('project', None)
    if project_name is None:
        return {'result': 'error', 'msg': 'Please provide a project name'}
    filepath = request.args.get('filepath', None)
    if filepath is None:
        return {'result': 'error', 'msg': 'No filepath provided'}

    max_content_size = request.args.get('max_size', str(MAX_TEST_SIZE))
    try:
        max_content_size = int(max_content_size)
    except ValueError:
        max_content_size = MAX_TEST_SIZE

    # If this is a local build do not look for project timestamps
    if is_local:
        source_code = extract_lines_from_source_code(project_name, '',
                                                     filepath, 0, 100000)
        if source_code is None:
            return {'result': 'error', 'msg': 'no source code'}
    else:
        latest_introspector_datestr = get_latest_introspector_date(
            project_name)
        if not latest_introspector_datestr:
            return {'result': 'error', 'msg': 'No introspector builds.'}

        source_code = extract_lines_from_source_code(
            project_name, latest_introspector_datestr, filepath, 0, 100000)

    if source_code is None:
        return {'result': 'error', 'msg': 'no source code'}

    # Deconstruct the buffer we want to return
    content_to_return = ""
    for line in source_code.split("\n"):
        if len(line) + len(content_to_return) < max_content_size:
            content_to_return += line + "\n"
        else:
            break

    # Try and close from the last "}", which in most cases should be a function
    # close indication.
    split_lines = content_to_return.split("\n")
    latest_closing = 0
    for idx, item in enumerate(split_lines):
        if item and item[0] == '}':
            latest_closing = idx
    if latest_closing > 0:
        content_to_return = "\n".join(split_lines[:latest_closing + 1])

    print("Latest closing: %d" % (latest_closing))
    return {'result': 'success', 'source_code': content_to_return}


@blueprint.route('/api/type-info')
def api_type_info():
    """Returns a json representation of all the functions in a given project"""
    project_name = request.args.get('project', None)
    if project_name is None:
        return {'result': 'error', 'msg': 'Please provide a project name'}
    type_name = request.args.get('name', None)
    if type_name is None:
        return {'result': 'error', 'msg': 'No function name provided'}

    print("Type name: %s" % (type_name))
    debug_info = data_storage.get_project_debug_report(project_name)
    return_elem = list()
    if debug_info is not None:
        for elem_type in debug_info.all_types:
            if elem_type.get('name') == type_name:
                return_elem.append(elem_type)
    if len(return_elem) > 0:
        return {'result': 'success', 'type_data': return_elem}

    return {'result': 'error', 'msg': 'Could not find type'}


@blueprint.route('/api/func-debug-types')
def function_debug_types():
    """Returns a json representation of all the functions in a given project"""
    project_name = request.args.get('project', None)
    if project_name is None:
        return {'result': 'error', 'msg': 'Please provide a project name'}

    function_signature = request.args.get('function_signature', None)
    if function_signature is None:
        return {'result': 'error', 'msg': 'No function signature provided'}

    # Get function from function signature
    target_function = get_function_from_func_signature(function_signature,
                                                       project_name)
    if target_function is None:
        return {'result': 'error', 'msg': 'Could not find function'}

    return {
        'result': 'succes',
        'arg-types': target_function.function_debug_arguments
    }


@blueprint.route('/api/function-signature')
def api_function_signature():
    """Returns a list of argument types extracted from debug information."""
    project_name = request.args.get('project', None)
    if project_name is None:
        return {'result': 'error', 'msg': 'Please provide a project name'}
    function_name = request.args.get('function', None)
    if function_name is None:
        return {'result': 'error', 'msg': 'No function name provided'}

    all_functions = data_storage.get_functions_by_project(project_name)
    all_functions = all_functions + data_storage.get_constructors_by_project(
        project_name)
    print("Iterating through all functions to match raw function name")
    for function in all_functions:
        if function.raw_function_name == function_name:
            return {
                'result': 'success',
                'signature': function.func_signature,
                'raw_data': function.debug_data,
            }

    return {'result': 'failed', 'msg': 'could not find specified function'}


@blueprint.route('/api/function-source-code')
def api_function_source_code():
    """Returns a json representation of all the functions in a given project"""
    project_name = request.args.get('project', None)
    if project_name is None:
        return {'result': 'error', 'msg': 'Please provide a project name'}

    function_signature = request.args.get('function_signature', None)
    if function_signature is None:
        return {'result': 'error', 'msg': 'No function signature provided'}

    # Get function from function signature
    target_function = get_function_from_func_signature(function_signature,
                                                       project_name)
    if target_function is None:
        return {'result': 'error', 'msg': 'Could not find function'}

    # Find latest introspector date
    latest_introspector_datestr = get_latest_introspector_date(project_name)
    if is_local:
        latest_introspector_datestr = "norelevant"

    if not latest_introspector_datestr:
        return {'result': 'error', 'msg': 'No introspector builds.'}

    src_begin = target_function.source_line_begin
    src_end = target_function.source_line_end
    src_file = target_function.function_filename

    # Check if we have accompanying debug info
    debug_source_dict = target_function.debug_data.get('source', None)
    if debug_source_dict:
        source_line = int(debug_source_dict.get('source_line', -1))
        if source_line != -1:
            src_begin = source_line

    source_code = extract_lines_from_source_code(
        project_name,
        latest_introspector_datestr,
        src_file,
        src_begin,
        src_end,
        sanity_check_function_end=True)
    if source_code is None:
        return {'result': 'error', 'msg': 'No source code'}
    return {
        'result': 'succes',
        'source': source_code,
        'filepath': src_file,
        'src_begin': src_begin,
        'src_end': src_end
    }


@blueprint.route('/api/function-with-matching-return-type')
def api_function_with_matching_type():
    """
        Returns a json representation of all the functions in a given project
        that match the needed return type
    """
    project_name = request.args.get('project', None)
    if project_name is None:
        return {'result': 'error', 'msg': 'Please provide a project name'}

    project = get_project_with_name(project_name)
    if project is None:
        return {'result': 'error', 'msg': 'Could not find project'}

    return_type = request.args.get('return-type', None)
    if return_type is None:
        return {
            'result': 'error',
            'msg': 'Please provide a matching return type'
        }

    matched_function_list = function_helper.search_function_by_return_type(
        data_storage.get_functions_by_project(project_name), return_type)
    matched_constructor_list = function_helper.search_function_by_return_type(
        data_storage.get_constructors_by_project(project_name), return_type)

    return {
        'result': 'success',
        'return-type': return_type,
        'constructors': matched_constructor_list,
        'functions': matched_function_list
    }


@blueprint.route('/api/jvm-method-properties')
def api_jvm_method_properties():
    """Returns some properties for the jvm method"""
    project_name = request.args.get('project', None)
    if project_name is None:
        return {'result': 'error', 'msg': 'Please provide a project name'}
    function_signature = request.args.get('function_signature', None)
    if function_signature is None:
        return {'result': 'error', 'msg': 'No function signature provided'}

    target_function = get_function_from_func_signature(function_signature,
                                                       project_name)

    if target_function is None:
        return {
            'result':
            'error',
            'msg':
            f'Function signature could not be found in project {project_name}'
        }

    return {
        'result': 'success',
        'is-jvm-static': target_function.is_static,
        'need-close': target_function.need_close,
        'exceptions': target_function.exceptions
    }


@blueprint.route('/api/get-all-tests')
def api_get_all_tests():
    """Returns the test files of all projects"""

    projects_tests = {}
    for project in data_storage.get_projects():
        light_tests = _light_project_tests(project.name)

        test_file_list = extract_project_tests(project.name)

        projects_tests[project.name] = {
            'light': light_tests,
            'normal': test_file_list
        }

    return {'result': 'success', 'project-tests': projects_tests}


def get_build_status_of_project(
        project_name: str) -> Optional[models.BuildStatus]:
    """Gets the current build status of a project."""
    build_status = data_storage.get_build_status()
    for bs in build_status:
        if bs.project_name == project_name:
            return bs
    return None


@blueprint.route('/api/easy-params-far-reach')
def api_oracle_2():
    """API for getting fuzz targets with easy fuzzable arguments."""
    err_msgs = list()
    project_name = request.args.get('project', None)
    if project_name is None:
        return {
            'result': 'error',
            'extended_msgs': ['Please provide project name']
        }

    no_static_funcs_arg = request.args.get('exclude-static-functions',
                                           'false').lower()
    if no_static_funcs_arg == 'true':
        no_static_functions = True
    else:
        no_static_functions = False

    only_functions_declared_in_header_files_arg = request.args.get(
        'only-with-header-file-declaration', 'false').lower()
    if only_functions_declared_in_header_files_arg == 'true':
        only_functions_declared_in_header_files = True
    else:
        only_functions_declared_in_header_files = False

    # Only refernced args
    only_referenced_functions_arg = request.args.get(
        'only-referenced-functions', 'false').lower()
    if only_referenced_functions_arg == 'true':
        only_referenced_functions = True
    else:
        only_referenced_functions = False

    target_project = get_project_with_name(project_name)
    if target_project is None:
        return {'result': 'error', 'extended_msgs': ['Project not found.']}

    all_functions = data_storage.get_functions_by_project(project_name)
    all_projects = [target_project]

    raw_interesting_functions = oracle_2(
        all_functions,
        all_projects,
        no_static_functions=no_static_functions,
        only_referenced_functions=only_referenced_functions,
        only_functions_declared_in_header_files=
        only_functions_declared_in_header_files)

    functions_to_return = function_helper.convert_functions_to_list_of_dict(
        raw_interesting_functions)

    if ALLOWED_ORACLE_RETURNS:
        functions_to_return = sort_funtions_to_return(functions_to_return)

    result_status = 'success'
    return {
        'result': result_status,
        'extended_msgs': err_msgs,
        'functions': functions_to_return
    }


@blueprint.route('/api/far-reach-low-cov-fuzz-keyword')
def api_oracle_1():
    err_msgs = list()
    project_name = request.args.get('project', None)
    if project_name is None:
        return {
            'result': 'error',
            'extended_msgs': ['Please provide project name']
        }

    no_static_funcs_arg = request.args.get('exclude-static-functions',
                                           'false').lower()
    if no_static_funcs_arg == 'true':
        no_static_functions = True
    else:
        no_static_functions = False

    # Only refernced args
    only_referenced_functions_arg = request.args.get(
        'only-referenced-functions', 'false').lower()
    if only_referenced_functions_arg == 'true':
        only_referenced_functions = True
    else:
        only_referenced_functions = False

    target_project = get_project_with_name(project_name)
    if not target_project:
        return {'result': 'error', 'extended_msgs': ['Could not find project']}

    all_functions = data_storage.get_functions_by_project(project_name)
    all_projects = [target_project]
    raw_functions = oracle_1(
        all_functions,
        all_projects,
        100,
        no_static_functions,
        only_referenced_functions=only_referenced_functions)
    functions_to_return = function_helper.convert_functions_to_list_of_dict(
        raw_functions)

    if ALLOWED_ORACLE_RETURNS:
        functions_to_return = sort_funtions_to_return(functions_to_return)

    result_status = 'success'
    return {
        'result': result_status,
        'extended_msgs': err_msgs,
        'functions': functions_to_return
    }


@blueprint.route('/api/project-repository')
def project_repository():
    project_name = request.args.get('project', None)
    if project_name is None:
        return {
            'result': 'error',
            'extended_msgs': ['Please provide project name']
        }

    target_project = get_project_with_name(project_name)
    if target_project is None:
        return {'result': 'error', 'extended_msgs': ['Did not find project']}
    return {
        'result': 'success',
        'project-repository': target_project.project_repository
    }


@blueprint.route('/api/far-reach-but-low-coverage')
def far_reach_but_low_coverage():
    """API that returns functions with far reach but low code coverage."""
    err_msgs = list()
    project_name = request.args.get('project', None)
    if project_name is None:
        return {
            'result': 'error',
            'extended_msgs': ['Please provide project name']
        }

    no_static_funcs_arg = request.args.get('exclude-static-functions',
                                           'false').lower()
    if no_static_funcs_arg == 'true':
        no_static_functions = True
    else:
        no_static_functions = False

    # Check for only using functions with cross references
    only_referenced_functions_arg = request.args.get(
        'only-referenced-functions', 'false').lower()
    if only_referenced_functions_arg == 'true':
        only_referenced_functions = True
    else:
        only_referenced_functions = False

    only_functions_declared_in_header_files_arg = request.args.get(
        'only-with-header-file-declaration', 'false').lower()
    if only_functions_declared_in_header_files_arg == 'true':
        only_functions_declared_in_header_files = True
    else:
        only_functions_declared_in_header_files = False

    target_project = get_project_with_name(project_name)
    if target_project is None:
        # Is the project a ghost project: a project that no longer
        # exists in OSS-Fuzz but is present on the ClusterFuzz instance.
        bs = get_build_status_of_project(project_name)

        if bs is None:
            return {
                'result':
                'error',
                'extended_msgs': [
                    'Project not in OSS-Fuzz (likely only contains a project.yaml file).'
                ]
            }
        err_msgs.append('Missing a recent introspector build.')

        # Check that builds are failing
        if bs.introspector_build_status is False:
            err_msgs.append(
                'No successful builds historically recently: introspector.')
        if bs.coverage_build_status is False:
            err_msgs.append('No successful builds: coverage.')
        if bs.fuzz_build_status is False:
            err_msgs.append('Build status failing: fuzzing.')
        if bs.introspector_build_status is False and bs.coverage_build_status is False and bs.fuzz_build_status is False:
            err_msgs.append('All builds failing.')
        elif bs.introspector_build_status is False and bs.coverage_build_status is False:
            err_msgs.append(
                'No data as no history of coverage or introspector builds.')

        if bs.language == 'N/A':
            err_msgs.append(
                'Project is a ghost (no longer in OSS-Fuzz repo, but in ClusterFuzz instance).'
            )
        return {'result': 'error', 'extended_msgs': err_msgs}

    # Get cross references
    if only_referenced_functions:
        xref_dict = get_cross_reference_dict_from_project(project_name)
    else:
        xref_dict = {}

    # Get functions of interest
    sorted_functions_of_interest = get_functions_of_interest(project_name)

    max_functions_to_show = 30
    functions_to_return = list()
    for function in sorted_functions_of_interest:
        if only_referenced_functions and function.name not in xref_dict:
            continue
        functions_to_return.append(function)

    if only_functions_declared_in_header_files:
        functions_to_return = remove_functions_with_header_declarations(
            functions_to_return)

    new_functions_to_return = []
    print("Iterating")
    for i in range(len(functions_to_return)):
        function = functions_to_return[i]
        if len(new_functions_to_return) >= max_functions_to_show:
            break
        if no_static_functions:
            # Exclude function if it's static
            if is_static(function):
                continue
        new_functions_to_return.append(function)

    functions_to_return = function_helper.convert_functions_to_list_of_dict(
        new_functions_to_return)

    # Assess if this worked well, and if not, provide a reason
    if len(functions_to_return) == 0:
        result_status = 'error'
        err_msgs.append('No functions found.')
        bs = get_build_status_of_project(project_name)

        if bs is None:
            return {
                'result':
                'error',
                'extended_msgs': [
                    'Project not in OSS-Fuzz (likely only contains a project.yaml file).'
                ]
            }

        # Check that builds are failing
        if bs.introspector_build_status is False:
            err_msgs.append('No successful build: introspector.')
        if bs.coverage_build_status is False:
            err_msgs.append('Build status failing: coverage.')
        if bs.fuzz_build_status is False:
            err_msgs.append('Build status failing: fuzzing.')
        if bs.introspector_build_status is False and bs.coverage_build_status is False and bs.fuzz_build_status is False:
            err_msgs.append('All builds failing.')
    else:
        result_status = 'success'

    if ALLOWED_ORACLE_RETURNS:
        functions_to_return = sort_funtions_to_return(functions_to_return)

    return {
        'result': result_status,
        'extended_msgs': err_msgs,
        'functions': functions_to_return
    }


def sort_funtions_to_return(functions_to_return):
    adjusted_functions = []
    for func in functions_to_return:
        if func['function_name'] not in ALLOWED_ORACLE_RETURNS:
            continue
        adjusted_functions.append(func)
    return adjusted_functions


def get_full_recursive_types(debug_type_dictionary, resulting_types,
                             target_type):
    """Recursively iterates atomic type elements to construct a friendly
    string representing the type."""
    print("Target type: %s" % (str(target_type)))
    if int(target_type) == 0:
        return ['void']

    type_to_query = target_type
    addresses_visited = set()
    to_visit = set()
    to_visit.add(type_to_query)

    while len(to_visit) > 0:
        type_to_query = to_visit.pop()

        if type_to_query in addresses_visited:
            continue
        addresses_visited.add(type_to_query)

        target_type = debug_type_dictionary.get(type_to_query, None)
        if target_type is None:
            print("Target is None")
            continue

        print("adding")
        resulting_types[type_to_query] = target_type
        print(target_type)

        addresses_visited.add(type_to_query)
        type_to_query = str(target_type.get('base_type_addr', ''))

        print("Type to query: " + type_to_query)
        if int(type_to_query) == 0:
            continue

        if target_type['tag'] == 'DW_TAG_structure_type':
            for elem_addr, elem_val in debug_type_dictionary.items():
                if elem_val['tag'] == "DW_TAG_member" and int(
                        elem_val['scope']) == int(type_to_query):
                    to_visit.add(str(elem_addr))

        to_visit.add(type_to_query)


@blueprint.route('/api/tester')
def tester():
    """Simple response tester."""
    return {'result': 'success', 'msg': 'tester'}


@blueprint.route('/api/shutdown')
def shutdown():
    """Shuts down the server, only if it's local."""
    if is_local or allow_shutdown:
        sig = getattr(signal, "SIGKILL", signal.SIGTERM)
        os.kill(os.getpid(), sig)
        return {'result': 'success', 'msg': 'shutdown'}
    else:
        return {'result': 'failed', 'msg': 'not a local server'}


@blueprint.route('/api/all-header-files')
def all_project_header_files():
    project = request.args.get('project', None)
    if project is None:
        return {
            'result': 'error',
            'extended_msgs': ['Please provide project name']
        }

    for elem in data_storage.ALL_HEADER_FILES:
        if elem['project'] == project:
            return {
                'result': 'success',
                'all-header-files': elem['all-header-files']
            }

    return {'result': 'failed', 'msg': 'did not find project'}


def should_ignore_testpath(test_path: str) -> bool:
    """Returns true if the test path should be ignored"""
    banned_paths = {
        '/src/fuzztest/', '/src/libfuzzer/', '/src/aflplusplus/', '/LPM/',
        '/googletest/', '/third_party/', '/thirdparty/', 'fuzz', '/depends/',
        '/external/', '/build/', '/src/inspector/', '/source-code/',
        '/workspace/'
    }
    if [bp for bp in banned_paths if bp in test_path]:
        return True
    return False


def extract_project_tests(project_name, refine: bool = True) -> List[str]:
    """Extracts the tests in terms of file paths of a given project"""
    tests_file = os.path.join(
        os.path.dirname(__file__),
        f"../static/assets/db/db-projects/{project_name}/test_files.json")
    if not os.path.isfile(tests_file):
        return []

    with open(tests_file, 'r') as f:
        tests_file_list = json.load(f)

    if refine:
        refined_list = []
        for test_file in tests_file_list:
            if should_ignore_testpath(test_file):
                continue
            refined_list.append(test_file)
        tests_file_list = refined_list
    return tests_file_list


def _light_project_tests(project_name):
    """Returns the list of test files in a project based on FI light."""
    target_project = get_project_with_name(project_name)
    if not target_project:
        return []

    if not target_project.light_analysis:
        return []

    light_test_files = target_project.light_analysis.get('test-files', [])
    returner_list = []
    for test_file in light_test_files:
        if should_ignore_testpath(test_file):
            continue
        returner_list.append(test_file)
    return returner_list


@blueprint.route('/api/project-tests')
def project_tests():
    """API that returns list of source files corresponding to tests of a
    project."""
    project = request.args.get('project', None)
    if project is None:
        return {
            'result': 'error',
            'extended_msgs': ['Please provide project name']
        }

    light_tests = _light_project_tests(project)
    test_file_list = extract_project_tests(project)
    combined = list(set(test_file_list + light_tests))
    if not combined:
        return {
            'result': 'error',
            'extended_msgs': ['Could not find tests file']
        }

    return {'result': 'success', 'test-file-list': combined}


@blueprint.route('/api/addr-to-recursive-dwarf-info')
def type_at_addr():
    # Temporary disabling this API because of size limit.
    # @arthurscchan 14/6/2024
    return {'result': 'error', 'extended_msgs': ['Temporary disabled']}
    project = request.args.get('project', None)
    if project is None:
        return {
            'result': 'error',
            'extended_msgs': ['Please provide project name']
        }

    addr = request.args.get('addr', None)
    if addr is None:
        return {
            'result': 'error',
            'extended_msgs': ['Please provide project name']
        }

    print("Opening type map")
    type_map = os.path.join(
        os.path.dirname(__file__),
        f"../static/assets/db/db-projects/{project}/type_map.json")

    with open(type_map, 'r') as f:
        type_map_dict = json.load(f)

    resulting_types = dict()
    print("Getting types")
    get_full_recursive_types(type_map_dict, resulting_types, addr)

    return {'result': 'success', 'dwarf-map': resulting_types}


@blueprint.route('/api/function-target-oracle')
def api_all_interesting_function_targets():
    """Returns a list of function targets based on analysis of all functions in all
    OSS-Fuzz projects (assuming they have introspetor builds) using several different
    heuristics."""
    result_dict = dict()

    # Get the list of all oracles that we have
    all_projects = data_storage.get_projects()

    # Extract all of the data needed for each function target
    functions_to_display = []
    funcs_max_to_display = 400
    total_funcs = set()
    oracle_pairs = [(oracle_1, "heuristic 1"), (oracle_2, "heuristic 2"),
                    (oracle_3, "heuristic 3")]
    for oracle, heuristic_name in oracle_pairs:
        for tmp_proj in data_storage.PROJECTS:
            if len(functions_to_display) > funcs_max_to_display:
                break
            proj_func_list = data_storage.get_functions_by_project(
                tmp_proj.name)
            func_targets = oracle(proj_func_list, all_projects)
            for func in func_targets:
                if func in total_funcs:
                    continue
                total_funcs.add(func)
                functions_to_display.append((func, heuristic_name))

    func_to_lang = dict()
    for func, heuristic in functions_to_display:
        language = 'c'
        for proj in all_projects:
            if proj.name == func.project:
                language = proj.language
                break
        # We may overwrite here, and in that case we just use the new
        # heuristic for labeling.
        func_to_lang[func.name] = language

    result_dict['result'] = 'success'

    # Rewrite list
    list_of_targets = []
    for func, heuristic_name in functions_to_display:
        dict_to_use = func.to_dict()

        list_of_targets.append({
            'function_target': dict_to_use,
            'heuristic': heuristic_name,
            'language': func_to_lang[func.name]
        })
    result_dict['function_targets'] = list_of_targets

    return result_dict


def get_cross_reference_dict_from_project(project_name) -> Dict[str, int]:
    # Get all functions of the target project
    project_functions = data_storage.get_functions_by_project(project_name)

    func_xrefs: Dict[str, int] = dict()
    for function in project_functions:
        callsites = function.callsites
        for cs_dst in callsites:
            func_xref_count = func_xrefs.get(cs_dst, 0)
            func_xref_count += 1
            func_xrefs[cs_dst] = func_xref_count
    return func_xrefs


@blueprint.route('/api/sample-cross-references')
def sample_cross_references():
    """Returns a list of strings with functions that call into a given 
    target function."""
    project_name = request.args.get('project', None)
    if project_name is None:
        return {'result': 'error', 'msg': 'Please provide a project name'}

    function_signature = request.args.get('function_signature', None)
    if function_signature is None:
        return {'result': 'error', 'msg': 'No function signature provided'}

    # Get function from function signature
    target_function = get_function_from_func_signature(function_signature,
                                                       project_name)
    if target_function is None:
        return {
            'result': 'error',
            'msg': 'Function signature could not be found'
        }
    function_name = target_function.raw_function_name

    # Get all functions of the target project
    project_functions = data_storage.get_functions_by_project(project_name)

    func_xrefs = []
    xrefs = []
    for function in project_functions:
        callsites = function.callsites
        for cs_dst in callsites:
            if cs_dst == function_name:
                func_xrefs.append(function)
                all_locations = function.callsites[cs_dst]
                for loc in all_locations:
                    filename = loc.split('#')[0]
                    cs_linenumber = int(loc.split(':')[-1])
                    xrefs.append({
                        'filename': function.function_filename,
                        'cs_linenumber': cs_linenumber,
                        'src_func': function.name,
                        'dst_func': function_name
                    })

    if is_local:
        latest_introspector_datestr = "notrelevant"
    else:
        latest_introspector_datestr = get_latest_introspector_date(
            project_name)

    if not latest_introspector_datestr:
        return {'result': 'error', 'msg': 'No introspector builds.'}

    source_code_xrefs = []
    for target_function in func_xrefs:
        src_begin = target_function.source_line_begin
        src_end = target_function.source_line_end
        src_file = target_function.function_filename

        # Don't show enormous functions
        if (src_end - src_begin) > 70:
            continue
        # Check if we have accompanying debug info
        debug_source_dict = target_function.debug_data.get('source', None)
        if debug_source_dict:
            source_line = int(debug_source_dict.get('source_line', -1))
            if source_line != -1:
                src_begin = source_line

        source_code = extract_lines_from_source_code(
            project_name,
            latest_introspector_datestr,
            src_file,
            src_begin,
            src_end,
            sanity_check_function_end=True)
        if source_code:
            source_code_xrefs.append(source_code)

    return {'result': 'success', 'source-code-refs': source_code_xrefs}
