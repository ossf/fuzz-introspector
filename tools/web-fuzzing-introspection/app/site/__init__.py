import os
import json

from .  import test_data
from . import models

def load_db():
    """Loads the database"""
    print("Loading db")
    db_timestamps_file = os.path.join(os.path.dirname(__file__), "../static/assets/db/db-timestamps.json")
    all_functions_file = os.path.join(os.path.dirname(__file__), "../static/assets/db/all-functions-db.json")
    project_timestamps_file = os.path.join(os.path.dirname(__file__), "../static/assets/db/all-project-timestamps.json")

    with open(all_functions_file, 'r') as f:
        all_function_list = json.load(f)

    idx = 0
    for func in all_function_list:
        idx += 1
        test_data.TEST_FUNCTIONS.append(
            models.Function(
                name = func['name'],
                project = func['project'],
                runtime_code_coverage = func['runtime_code_coverage'],
                function_filename = func['function_filename'],
                reached_by_fuzzers = 0,
                code_coverage_url = func['code_coverage_url'],
                is_reached = func['is_reached']
            )
        )
    print("Loadded %d functions"%(idx))
    print("Len %d"%(len(test_data.TEST_FUNCTIONS)))

    # Load all profiles
    with open(project_timestamps_file, 'r') as f:
        all_project_timestamps_json = json.load(f)
    for project_timestamp in all_project_timestamps_json:
        test_data.TEST_PROJECTS.append(
            models.Project(
                name=project_timestamp['project_name'],
                language='c',
                fuzz_count=project_timestamp['fuzzer_count'],
                reach = project_timestamp['static_reachability'],
                runtime_cov=project_timestamp['coverage_lines'],
                introspector_report_url=project_timestamp['introspector_report_url'],
                code_coverage_report_url=project_timestamp['coverage_url']
            )
        )
    return

load_db()