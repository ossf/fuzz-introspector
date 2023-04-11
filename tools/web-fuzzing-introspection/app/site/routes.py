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

from flask import Blueprint, render_template, request

from app.site import models

# Use these during testing.
from app.site import test_data

site = Blueprint('site', __name__, template_folder='templates')


def get_frontpage_summary_stats():
    # Get total number of projects
    all_projects = test_data.get_projects()
    total_number_of_projects = len(all_projects)
    total_fuzzers = sum([project.fuzz_count for project in all_projects])
    total_functions = len(test_data.get_functions())
    language_count = {'c' : 0, 'python': 0, 'c++': 0, 'java': 0}
    for project in all_projects:
        language_count[project.language] += 1

    # wrap it in a DBSummary
    db_summary = models.DBSummary(all_projects, total_number_of_projects, total_fuzzers, total_functions, language_count)
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

@site.route('/')
def index():
    db_summary = get_frontpage_summary_stats()
    db_timestamps = test_data.TEST_DB_TIMESTAMPS
    return render_template('index.html', db_summary = db_summary, db_timestamps = db_timestamps)


@site.route('/function-profile', methods=['GET'])
def function_profile():
    function_profile = get_fuction_with_name(request.args.get('function', 'none'), request.args.get('project', 'none'))

    related_functions = get_all_related_functions(function_profile)
    return render_template('function-profile.html', related_functions = related_functions, function_profile = function_profile)


@site.route('/project-profile', methods=['GET'])
def project_profile():
    #print(request.args.get('project', 'none'))
    project = get_project_with_name(request.args.get('project', 'none'))
    project_statistics = test_data.TEST_PROJECT_TIMESTAMPS
    return render_template('project-profile.html', project=project, project_statistics=project_statistics)


@site.route('/function-search')
def function_search():
    print("Showing functions overview")
    query = request.args.get('q', '')
    print("query: { %s }"%(query))

    if query == '':
        # Pick 25 random functions per default
        functions_to_display = test_data.get_functions()[0:20]
    else:
        tmp_list = []
        for function in test_data.get_functions():
            if query in function.name:
                tmp_list.append(function)
        functions_to_display = tmp_list

    return render_template('function-search.html', all_functions=functions_to_display)


@site.route('/projects-overview')
def projects_overview():
    projects = test_data.get_projects()
    return render_template('projects-overview.html', all_projects=projects)
