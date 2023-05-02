import os
import json

from .  import test_data
from . import models
from . import db_manager


def update_db():
    print("Updating DB")
    db_out_dir = os.path.join(os.path.dirname(__file__), "../static/assets/db/")
    db_in_dir = os.path.join(os.path.dirname(__file__), "../static/assets/db/")
    db_manager.create_db(20, 5, db_out_dir, db_in_dir, 1, False)
    print("DB updated")

def is_db_valid():
    db_timestamps_file = os.path.join(os.path.dirname(__file__), "../static/assets/db/db-timestamps.json")
    if not os.path.isfile(db_timestamps_file):
        return False

def load_db():
    """Loads the database"""
    print("Loading db")
    if not is_db_valid():
        update_db()

    db_timestamps_file = os.path.join(os.path.dirname(__file__), "../static/assets/db/db-timestamps.json")
    all_functions_file = os.path.join(os.path.dirname(__file__), "../static/assets/db/all-functions-db.json")
    project_timestamps_file = os.path.join(os.path.dirname(__file__), "../static/assets/db/all-project-timestamps.json")
    project_currents = os.path.join(os.path.dirname(__file__), "../static/assets/db/all-project-current.json")
    if len(test_data.TEST_DB_TIMESTAMPS) > 0:
        return

    with open(db_timestamps_file, 'r') as f:
        db_tss = json.load(f)
    for ts in db_tss:
        test_data.TEST_DB_TIMESTAMPS.append(
            models.DBTimestamp(
                date = ts['date'],
                project_count = ts['project_count'],
                fuzzer_count = ts['fuzzer_count'],
                function_count = ts['function_count']
            )
        )

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

    with open(project_timestamps_file, 'r') as f:
        project_timestamps_json = json.load(f)
    for project_timestamp in project_timestamps_json:
        test_data.TEST_PROJECT_TIMESTAMPS.append(
            models.ProjectTimestamp(
				date = project_timestamp['date'],
				project_name = project_timestamp['project_name'],
				coverage_lines = project_timestamp['coverage_lines'],
				static_reachability = project_timestamp['static_reachability'],
				fuzzer_count = project_timestamp['fuzzer_count'],
                coverage_functions = project_timestamp['coverage_lines']
            )
        )

    # Load all profiles
    with open(project_currents, 'r') as f:
        project_currents_json = json.load(f)
    for project_timestamp in project_currents_json:
        test_data.TEST_PROJECTS.append(
            models.Project(
                name=project_timestamp['project_name'],
                language=project_timestamp.get('language', 'c'),
                fuzz_count=project_timestamp['fuzzer_count'],
                reach = project_timestamp['static_reachability'],
                runtime_cov=project_timestamp['coverage_lines'],
                introspector_report_url=project_timestamp['introspector_report_url'],
                code_coverage_report_url=project_timestamp['coverage_url']
            )
        )
    return
