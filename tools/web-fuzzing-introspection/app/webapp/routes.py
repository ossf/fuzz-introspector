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

from flask import Blueprint, render_template, request

#from app.site import models
from . import models

# Use these during testing.
#from app.site import test_data
from . import test_data

blueprint = Blueprint('site', __name__, template_folder='templates')


def get_frontpage_summary_stats():
    # Get total number of projects
    all_projects = test_data.get_projects()
    total_number_of_projects = len(all_projects)
    total_fuzzers = sum([project.fuzz_count for project in all_projects])
    total_functions = len(test_data.get_functions())
    language_count = {'c': 0, 'python': 0, 'c++': 0, 'java': 0}
    for project in all_projects:
        language_count[project.language] += 1

    # wrap it in a DBSummary
    db_summary = models.DBSummary(all_projects, total_number_of_projects,
                                  total_fuzzers, total_functions,
                                  language_count)
    return db_summary


def get_project_with_name(project_name):
    all_projects = test_data.get_projects()
    for project in all_projects:
        if project.name == project_name:
            return project

    # TODO: Handle the case where there is no such project.
    return all_projects[0]


def get_fuction_with_name(function_name, project_name):
    all_functions = test_data.get_functions()
    for function in all_functions:
        if function.name == function_name and function.project == project_name:
            return function

    # TODO: Handle the case where there is no such function
    return all_functions[0]


def get_all_related_functions(primary_function):
    all_functions = test_data.get_functions()
    related_functions = []
    for function in all_functions:
        if function.name == primary_function.name and function.project != primary_function.project:
            related_functions.append(function)
    return related_functions


@blueprint.route('/')
def index():
    db_summary = get_frontpage_summary_stats()
    db_timestamps = test_data.TEST_DB_TIMESTAMPS
    print("Length of timestamps: %d" % (len(db_timestamps)))
    # Maximum projects
    max_proj = 0
    max_fuzzer_count = 0
    max_function_count = 0
    for db_timestamp in db_timestamps:
        max_proj = max(db_timestamp.project_count, max_proj)
        max_fuzzer_count = max(db_timestamp.fuzzer_count, max_fuzzer_count)
        max_function_count = max(db_timestamp.function_count,
                                 max_function_count)

    max_proj = int(max_proj * 1.2)
    max_fuzzer_count = int(max_fuzzer_count * 1.2)
    max_function_count = int(max_function_count * 1.2)

    return render_template('index.html',
                           db_summary=db_summary,
                           db_timestamps=db_timestamps,
                           max_proj=max_proj,
                           max_fuzzer_count=max_fuzzer_count,
                           max_function_count=max_function_count)


@blueprint.route('/function-profile', methods=['GET'])
def function_profile():
    function_profile = get_fuction_with_name(
        request.args.get('function', 'none'),
        request.args.get('project', 'none'))

    related_functions = get_all_related_functions(function_profile)
    return render_template('function-profile.html',
                           related_functions=related_functions,
                           function_profile=function_profile)


@blueprint.route('/project-profile', methods=['GET'])
def project_profile():
    #print(request.args.get('project', 'none'))
    project = get_project_with_name(request.args.get('project', 'none'))
    project_statistics = test_data.TEST_PROJECT_TIMESTAMPS
    real_stats = []
    for ps in project_statistics:
        if ps.project_name == project.name:
            real_stats.append(ps)
    return render_template('project-profile.html',
                           project=project,
                           project_statistics=real_stats)


@blueprint.route('/function-search')
def function_search():
    info_msg = None
    MAX_MATCHES_TO_DISPLAY = 900
    query = request.args.get('q', '')
    print("query: { %s }" % (query))
    print("Length of functions: %d" % (len(test_data.get_functions())))
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
        for function in test_data.get_functions():
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
        for function in test_data.get_functions():
            if query in function.name:
                tmp_list.append(function)
        functions_to_display = tmp_list

        total_matches = len(functions_to_display)
        if total_matches >= MAX_MATCHES_TO_DISPLAY:
            functions_to_display = functions_to_display[
                0:MAX_MATCHES_TO_DISPLAY]
            info_msg = f"Found {total_matches} matches. Only showing the first {MAX_MATCHES_TO_DISPLAY}."

    return render_template('function-search.html',
                           all_functions=functions_to_display,
                           info_msg=info_msg)


@blueprint.route('/projects-overview')
def projects_overview():
    projects = test_data.get_projects()
    return render_template('projects-overview.html', all_projects=projects)


@blueprint.route('/about')
def about():
    return render_template('about.html')


@blueprint.route('/api/project-summary')
def api_project_summary():
    project_name = request.args.get('project', None)
    if project_name == None:
        return {'result': 'error', 'msg': 'Please provide project name'}
    target_project = None
    all_projects = test_data.get_projects()
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
            'fuzzer-count': target_project.fuzz_count,
            'runtime-coverage': project.runtime_cov,
            'static-reachability': project.reach
        }
    }


@blueprint.route('/api/branch-blockers')
def branch_blockers():
    project_name = request.args.get('project', None)
    if project_name == None:
        return {'result': 'error', 'msg': 'Please provide project name'}

    target_project = None
    all_projects = test_data.get_projects()
    for project in all_projects:
        if project.name == project_name:
            target_project = project
            break
    if target_project is None:
        return {'result': 'error', 'msg': 'Project not in the database'}

    all_branch_blockers = test_data.get_blockers()

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
    all_projects = test_data.get_projects()
    for project in all_projects:
        if project.name == project_name:
            target_project = project
            break
    if target_project is None:
        return {'result': 'error', 'msg': 'Project not in the database'}

    all_functions = test_data.get_functions()
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

    max_functions_to_show = 30
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
            function.accummulated_cyclomatic_complexity
        })

    return {'result': 'succes', 'functions': functions_to_return}
