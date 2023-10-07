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
import json

from flask import Blueprint, render_template, request, redirect

#from app.site import models
from . import models

# Use these during testing.
#from app.site import test_data
from . import data_storage

blueprint = Blueprint('site', __name__, template_folder='templates')

gtag = None


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
        project_statistics = data_storage.PROJECT_TIMESTAMPS
        real_stats = []
        for ps in project_statistics:
            if ps.project_name == project.name:
                real_stats.append(ps)

        return render_template('project-profile.html',
                               gtag=gtag,
                               project=project,
                               project_statistics=real_stats,
                               has_project_details=True)

    # Either this is a wrong project or we only have a build status for it
    all_build_status = data_storage.get_build_status()
    for build_status in all_build_status:
        if build_status.project_name == target_project_name:
            project = models.Project(name=build_status.project_name,
                                     language=build_status.language,
                                     date="",
                                     fuzzer_count=0,
                                     coverage_data=None,
                                     introspector_data=None)

            return render_template('project-profile.html',
                                   gtag=gtag,
                                   project=project,
                                   project_statistics=None,
                                   has_project_details=False)
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
    all_projects = data_storage.get_projects()
    projects_to_use = []
    # Only include fuzz introspector projects
    for project in all_projects:
        #if project.introspector_data != None:
        projects_to_use.append(project)
    return render_template('projects-overview.html',
                           gtag=gtag,
                           all_projects=projects_to_use)


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
                'annotated-cfg': project.introspector_data['annotated_cfg'],
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
            'runtime-coverage-data': project.coverage_data,
            'introspector-data': project.introspector_data
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
                'project-name':
                blocker.project_name,
                'function-name':
                blocker.function_name,
                'unique_blocked_coverage':
                blocker.unique_blocked_coverage
            })
    return {'result': 'success', 'project-blockers': project_blockers}


@blueprint.route('/api/far-reach-but-low-coverage')
def far_reach_but_low_coverage():
    project_name = request.args.get('project', None)
    if project_name == None:
        return {'result': 'error', 'msg': 'Please provide project name'}  ##

    target_project = None
    all_projects = data_storage.get_projects()
    for project in all_projects:
        if project.name == project_name:
            target_project = project
            break
    if target_project is None:
        return {'result': 'error', 'msg': 'Project not in the database'}

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

    max_functions_to_show = 1000
    functions_to_return = list()
    idx = 0
    for function in sorted_functions_of_interest:
        if idx >= max_functions_to_show:
            break
        idx += 1
        functions_to_return.append({
            'function-name':
            function.name,
            'function_filename':
            function.function_filename,
            'runtime-coverage-percent':
            function.runtime_code_coverage,
            'accummulated-complexity':
            function.accummulated_cyclomatic_complexity,
            'function-arguments':
            function.function_arguments,
            'function-argument-names':
            function.function_argument_names,
            'return-type':
            function.return_type,
            'is-reached':
            function.is_reached,
            'reached-by-fuzzers':
            function.reached_by_fuzzers,
            'raw-function-name':
            function.raw_function_name,
        })

    return {'result': 'succes', 'functions': functions_to_return}
