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

import random
import requests
import json

from flask import Blueprint, render_template, request, redirect

#from app.site import models
from . import models

# Use these during testing.
#from app.site import test_data
from . import data_storage

blueprint = Blueprint('site', __name__, template_folder='templates')

gtag = None


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


def extract_introspector_raw_source_code(project_name, date_str, target_file):
    introspector_summary_url = get_introspector_report_url_source_base(
        project_name, date_str.replace("-", "")) + target_file

    print("URL: %s" % (introspector_summary_url))
    # Read the introspector atifact
    try:
        raw_source = requests.get(introspector_summary_url, timeout=10).text
    except:
        return None

    return raw_source


def extract_lines_from_source_code(project_name,
                                   date_str,
                                   target_file,
                                   line_begin,
                                   line_end,
                                   print_line_numbers=False):
    print("Getting source")
    raw_source = extract_introspector_raw_source_code(project_name, date_str,
                                                      target_file)
    if raw_source is None:
        print("Raw source is None")
        return raw_source

    source_lines = raw_source.split("\n")

    return_source = ""
    max_length = len(str(line_end))
    for line_num in range(line_begin, line_end):
        if line_num >= len(source_lines):
            continue

        if print_line_numbers:
            line_num_str = " " * (max_length - len(str(line_num)))
            return_source += "%s%d " % (line_num_str, line_num)
        return_source += source_lines[line_num] + "\n"
    return return_source


def get_functions_of_interest(project_name):
    all_functions = data_storage.get_functions()
    project_functions = []
    for function in all_functions:
        if function.project == project_name:
            if function.runtime_code_coverage < 20.0:
                project_functions.append(function)

    # Filter based on accummulated cyclomatic complexity and low coverage
    sorted_functions_of_interest = sorted(
        project_functions,
        key=lambda x:
        (-x.accummulated_cyclomatic_complexity, -x.runtime_code_coverage))

    return sorted_functions_of_interest


def get_frontpage_summary_stats():
    # Get total number of projects
    all_projects = data_storage.get_projects()

    projects_to_use = []
    # Only include fuzz introspector projects
    #for project in all_projects:
    #    if project.introspector_data != None:
    #        projects_to_use.append(project)

    total_number_of_projects = len(all_projects)
    total_fuzzers = sum([project.fuzzer_count for project in all_projects])
    total_functions = len(data_storage.get_functions())
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


def get_project_with_name(project_name):
    all_projects = data_storage.get_projects()
    for project in all_projects:
        if project.name == project_name:
            return project

    # TODO: Handle the case where there is no such project.
    return None


def get_fuction_with_name(function_name, project_name):
    all_functions = data_storage.get_functions()
    for function in all_functions:
        if function.name == function_name and function.project == project_name:
            return function

    # TODO: Handle the case where there is no such function
    return all_functions[0]


def get_all_related_functions(primary_function):
    all_functions = data_storage.get_functions()
    related_functions = []
    for function in all_functions:
        if function.name == primary_function.name and function.project != primary_function.project:
            related_functions.append(function)
    return related_functions


@blueprint.route('/')
def index():
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
    return render_template('index.html',
                           gtag=gtag,
                           db_summary=db_summary,
                           db_timestamps=db_timestamps,
                           max_proj=max_proj,
                           max_fuzzer_count=max_fuzzer_count,
                           max_function_count=max_function_count,
                           oss_fuzz_total_number=oss_fuzz_total_number,
                           max_line_count=max_line_count)


@blueprint.route('/function-profile', methods=['GET'])
def function_profile():
    function_profile = get_fuction_with_name(
        request.args.get('function', 'none'),
        request.args.get('project', 'none'))

    related_functions = get_all_related_functions(function_profile)
    return render_template('function-profile.html',
                           gtag=gtag,
                           related_functions=related_functions,
                           function_profile=function_profile)


@blueprint.route('/project-profile', methods=['GET'])
def project_profile():
    #print(request.args.get('project', 'none'))

    target_project_name = request.args.get('project', 'none')

    project = get_project_with_name(target_project_name)

    if project != None:
        # Get the build status of the project
        all_build_status = data_storage.get_build_status()
        project_build_status = dict()
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
        for ps in project_statistics:
            if ps.project_name == project.name:
                real_stats.append(ps)
                datestr = ps.date
                latest_statistics = ps
                latest_coverage_report = get_coverage_report_url(
                    build_status.project_name, datestr, build_status.language)
                if ps.introspector_data != None:
                    latest_fuzz_introspector_report = get_introspector_url(
                        build_status.project_name, datestr)
                    latest_introspector_datestr = datestr

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
            latest_introspector_datestr=latest_introspector_datestr)

    # Either this is a wrong project or we only have a build status for it
    all_build_status = data_storage.get_build_status()
    for build_status in all_build_status:
        if build_status.project_name == target_project_name:
            project = models.Project(
                name=build_status.project_name,
                language=build_status.language,
                date="",
                fuzzer_count=0,
                coverage_data=None,
                introspector_data=None,
            )

            # Get statistics of the project
            project_statistics = data_storage.PROJECT_TIMESTAMPS
            real_stats = []
            datestr = None
            latest_statistics = None
            latest_coverage_report = None
            latest_fuzz_introspector_report = None
            latest_introspector_datestr = ""
            for ps in project_statistics:
                if ps.project_name == project.name:
                    real_stats.append(ps)
                    datestr = ps.date
                    latest_statistics = ps
                    latest_coverage_report = get_coverage_report_url(
                        build_status.project_name, datestr,
                        build_status.language)
                    if ps.introspector_data != None:
                        latest_fuzz_introspector_report = get_introspector_url(
                            build_status.project_name, datestr)
                        latest_introspector_datestr = datestr

            if len(real_stats) > 0:
                latest_coverage_report = get_coverage_report_url(
                    build_status.project_name, datestr, build_status.language)
            else:
                latest_coverage_report = None
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
                latest_statistics=latest_statistics,
                latest_introspector_datestr=latest_introspector_datestr)
    print("Nothing to do. We shuold probably have a 404")
    return redirect("/")


@blueprint.route('/function-search')
def function_search():
    info_msg = None
    MAX_MATCHES_TO_DISPLAY = 900
    query = request.args.get('q', '')
    print("query: { %s }" % (query))
    print("Length of functions: %d" % (len(data_storage.get_functions())))
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
        for function in data_storage.get_functions():
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
        for function in data_storage.get_functions():
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
                           info_msg=info_msg)


@blueprint.route('/projects-overview')
def projects_overview():
    # Get statistics of the project
    project_statistics = data_storage.PROJECT_TIMESTAMPS
    latest_coverage_profiles = dict()
    real_stats = []
    latest_statistics = None
    for ps in project_statistics:
        latest_coverage_profiles[ps.project_name] = ps

    return render_template('projects-overview.html',
                           gtag=gtag,
                           all_projects=latest_coverage_profiles.values())


def oracle_3(all_functions, all_projects):
    """Filters fucntions that:
    - "have far reach but low coverage and are likely easy to trigger"

    More technically, functions with:
        - a low code coevrage percent in the function itself;
        - a high accummulated cyclomatic complexity;
        - less than a certain number of arguments (3 or below);
        - at least one argument.
    """
    all_functions = data_storage.get_functions()
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

            # If there is only a single argument then we want it to be something that is "fuzzable", i.e.
            # either a string or a char pointer.
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

    for project_name, functions in projects_added.items():
        functions_of_interest += functions
    return functions_of_interest


def oracle_1(all_functions, all_projects):
    tmp_list = []
    project_count = dict()
    for function in all_functions:
        if "parse" not in function.name:
            continue

        if (function.runtime_code_coverage == 0.0
                and project_count.get(function.project, 0) < 5
                and function.accummulated_cyclomatic_complexity > 200):

            to_continue = False
            for proj in all_projects:
                if proj.name == function.project and proj.language in {
                        'c', 'c++'
                }:
                    to_continue = True
            if not to_continue:
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


def oracle_2(all_functions, all_projects):
    tmp_list = []
    project_count = dict()
    for function in all_functions:
        if len(function.function_arguments) != 2:
            continue

        if (function.function_arguments[0] != 'char *'
                or function.function_arguments[1] != "int"):
            continue

        if function.accummulated_cyclomatic_complexity < 150:
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


@blueprint.route('/target_oracle')
def target_oracle():
    all_projects = data_storage.get_projects()
    all_functions = data_storage.get_functions()

    functions_to_display = []

    total_funcs = set()
    oracle_pairs = [(oracle_1, "heuristic 1"), (oracle_2, "heuristic 2"),
                    (oracle_3, "heuristic 3")]
    for oracle, heuristic_name in oracle_pairs:
        func_targets = oracle(all_functions, all_projects)
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

    return render_template('target-oracle.html',
                           gtag=gtag,
                           functions_to_display=functions_to_display,
                           func_to_lang=func_to_lang)


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
                           languages_summarised=languages_summarised)


@blueprint.route('/about')
def about():
    return render_template('about.html', gtag=gtag)


@blueprint.route('/api')
def api():
    return render_template('api.html', gtag=gtag)


@blueprint.route('/api/annotated-cfg')
def api_annotated_cfg():
    project_name = request.args.get('project', None)
    if project_name == None:
        return {'result': 'error', 'msg': 'Please provide project name'}

    target_project = None
    all_projects = data_storage.get_projects()
    for project in all_projects:
        if project.name == project_name:
            target_project = project
            break
    if target_project is None:
        return {'result': 'error', 'msg': 'Project not in the database'}

    try:
        return {
            'result': 'success',
            'project': {
                'name': project_name,
                'annotated_cfg': project.introspector_data['annotated_cfg'],
            }
        }
    except KeyError:
        return {'result': 'error', 'msg': 'Found no annotated CFG data.'}
    except TypeError:
        return {'result': 'error', 'msg': 'Found no introspector data.'}


@blueprint.route('/api/project-summary')
def api_project_summary():
    project_name = request.args.get('project', None)
    if project_name == None:
        return {'result': 'error', 'msg': 'Please provide project name'}
    target_project = None
    all_projects = data_storage.get_projects()
    for project in all_projects:
        if project.name == project_name:
            target_project = project
            break
    if target_project is None:
        return {'result': 'error', 'msg': 'Project not in the database'}

    return {
        'result': 'success',
        'project': {
            'name': project_name,
            'runtime_coverage_data': project.coverage_data,
            'introspector_data': project.introspector_data
        }
    }


@blueprint.route('/api/branch-blockers')
def branch_blockers():
    project_name = request.args.get('project', None)
    if project_name == None:
        return {'result': 'error', 'msg': 'Please provide project name'}

    target_project = None
    all_projects = data_storage.get_projects()
    for project in all_projects:
        if project.name == project_name:
            target_project = project
            break
    if target_project is None:
        return {'result': 'error', 'msg': 'Project not in the database'}

    all_branch_blockers = data_storage.get_blockers()

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


@blueprint.route('/api/all-functions')
def api_project_all_functions():
    """Returns a json representation of all the functions in a given project"""
    project_name = request.args.get('project', None)
    if project_name == None:
        return {'result': 'error', 'msg': 'Please provide a project name'}

    # Get all of the functions
    all_functions = data_storage.get_functions()
    project_functions = []
    for function in all_functions:
        if function.project == project_name:
            project_functions.append(function)

    # Convert it to something we can return
    functions_to_return = list()
    for function in project_functions:
        functions_to_return.append({
            'function_name':
            function.name,
            'function_filename':
            function.function_filename,
            'raw_function_name':
            function.raw_function_name,
            'is_reached':
            function.is_reached,
            'accummulated_complexity':
            function.accummulated_cyclomatic_complexity,
            'function_argument_names':
            function.function_argument_names,
            'function_arguments':
            function.function_arguments,
            'reached_by_fuzzers':
            function.reached_by_fuzzers,
            'return_type':
            function.return_type,
            'runtime_coverage_percent':
            function.runtime_code_coverage,
        })
    return {'result': 'success', 'functions': functions_to_return}


@blueprint.route('/api/function-source-code')
def api_function_source_code():
    """Returns a json representation of all the functions in a given project"""
    project_name = request.args.get('project', None)
    if project_name == None:
        return {'result': 'error', 'msg': 'Please provide a project name'}
    function_name = request.args.get('function', None)
    if function_name == None:
        return {'result': 'error', 'msg': 'No function name provided'}

    # Get all of the function
    all_functions = data_storage.get_functions()
    project_functions = []
    for function in all_functions:
        if function.project == project_name:
            project_functions.append(function)

    all_build_status = data_storage.get_build_status()
    latest_introspector_datestr = None
    for build_status in all_build_status:
        if build_status.project_name == project_name:

            # Get statistics of the project
            project_statistics = data_storage.PROJECT_TIMESTAMPS
            for ps in project_statistics:
                if ps.project_name == project_name:
                    datestr = ps.date
                    if ps.introspector_data != None:
                        latest_introspector_datestr = datestr

    if latest_introspector_datestr == None:
        return {'result': 'error', 'msg': 'No introspector builds.'}

    for function in project_functions:
        if function.name == function_name or function.raw_function_name == function_name:
            src_begin = function.source_line_begin
            src_end = function.source_line_end
            src_file = function.function_filename
            source_code = extract_lines_from_source_code(
                project_name, latest_introspector_datestr, src_file, src_begin,
                src_end)
            if source_code == None:
                return {'result': 'error', 'msg': 'No source code'}
            return {
                'result': 'succes',
                'source': source_code,
                'filepath': src_file,
                'src_begin': src_begin,
                'src_end': src_begin
            }
    return {'result': 'error', 'msg': 'did not find function'}


def get_build_status_of_project(project_name):
    build_status = data_storage.get_build_status()

    languages_summarised = dict()
    for bs in build_status:
        if bs.project_name == project_name:
            return bs

    return None


@blueprint.route('/api/far-reach-but-low-coverage')
def far_reach_but_low_coverage():
    err_msgs = list()
    project_name = request.args.get('project', None)
    if project_name == None:
        return {
            'result': 'error',
            'extended_msgs': ['Please provide project name']
        }

    target_project = None
    all_projects = data_storage.get_projects()
    for project in all_projects:
        if project.name == project_name:
            target_project = project
            break
    if target_project is None:
        # Is the project a ghost project: a project that no longer
        # exists in OSS-Fuzz but is present on the ClusterFuzz instance.
        bs = get_build_status_of_project(project_name)

        if bs == None:
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

    # Get functions of interest
    sorted_functions_of_interest = get_functions_of_interest(project_name)

    max_functions_to_show = 1000
    functions_to_return = list()
    idx = 0
    for function in sorted_functions_of_interest:
        if idx >= max_functions_to_show:
            break
        idx += 1
        functions_to_return.append({
            'function_name': function.name,
            'function_filename': function.function_filename,
            'runtime_coverage_percent': function.runtime_code_coverage,
            'accummulated_complexity':
            function.accummulated_cyclomatic_complexity,
            'function_arguments': function.function_arguments,
            'function_argument_names': function.function_argument_names,
            'return_type': function.return_type,
            'is_reached': function.is_reached,
            'reached_by_fuzzers': function.reached_by_fuzzers,
            'raw_function_name': function.raw_function_name,
            'source_line_begin': function.source_line_begin,
            'source_line_end': function.source_line_end
        })

    # Assess if this worked well, and if not, provide a reason
    if len(functions_to_return) == 0:
        result_status = 'error'
        err_msgs.append('No functions found.')
        bs = get_build_status_of_project(project_name)

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

    return {
        'result': result_status,
        'extended_msgs': err_msgs,
        'functions': functions_to_return
    }


@blueprint.route('/api/function-target-oracle')
def api_all_interesting_function_targets():
    """Returns a list of function targets based on analysis of all functions in all
    OSS-Fuzz projects (assuming they have introspetor builds) using several different
    heuristics."""
    result_dict = dict()

    # Get the list of all oracles that we have
    all_projects = data_storage.get_projects()
    all_functions = data_storage.get_functions()

    # Extract all of the data needed for each function target
    functions_to_display = []

    total_funcs = set()
    oracle_pairs = [(oracle_1, "heuristic 1"), (oracle_2, "heuristic 2"),
                    (oracle_3, "heuristic 3")]
    for oracle, heuristic_name in oracle_pairs:
        func_targets = oracle(all_functions, all_projects)
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
        dict_to_use = func.__dict__()

        list_of_targets.append({
            'function_target': dict_to_use,
            'heuristic': heuristic_name,
            'language': func_to_lang[func.name]
        })
    result_dict['function_targets'] = list_of_targets

    return result_dict
