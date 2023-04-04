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

from flask import Blueprint, render_template

from app.site import models

# Use these during testing.
from app.site import test_data

site = Blueprint('site', __name__, template_folder='templates')


@site.route('/')
def index():
    return render_template('index.html')

@site.route('/function-profile')
def function_profile():
    related_functions = test_data.get_functions()
    return render_template('function-profile.html', related_functions = related_functions)

@site.route('/project-profile')
def project_profile():
    project = test_data.get_projects()[0]
    return render_template('project-profile.html', project=project)

@site.route('/function-search')
def function_search():
    functions = test_data.get_functions()
    return render_template('function-search.html', all_functions=functions)

@site.route('/projects-overview')
def projects_overview():
    projects = test_data.get_projects()
    return render_template('projects-overview.html', all_projects=projects)
