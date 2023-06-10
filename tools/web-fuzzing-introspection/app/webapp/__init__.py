import os
import json

from . import test_data
from . import models


def is_db_valid():
    db_timestamps_file = os.path.join(
        os.path.dirname(__file__), "../static/assets/db/db-timestamps.json")
    if not os.path.isfile(db_timestamps_file):
        return False
    return True


def load_db():
    """Loads the database"""
    print("Loading db")
    if not is_db_valid():
        update_db()

    db_timestamps_file = os.path.join(
        os.path.dirname(__file__), "../static/assets/db/db-timestamps.json")
    all_functions_file = os.path.join(
        os.path.dirname(__file__), "../static/assets/db/all-functions-db.json")
    all_branch_blockers_file = os.path.join(
        os.path.dirname(__file__), "../static/assets/db/all-branch-blockers.json")
    project_timestamps_file = os.path.join(
        os.path.dirname(__file__),
        "../static/assets/db/all-project-timestamps.json")
    project_currents = os.path.join(
        os.path.dirname(__file__),
        "../static/assets/db/all-project-current.json")
    projects_build_status = os.path.join(
        os.path.dirname(__file__),
        "../static/assets/db/build-status.json")

    if len(test_data.TEST_DB_TIMESTAMPS) > 0:
        return

    with open(db_timestamps_file, 'r') as f:
        db_tss = json.load(f)
    for ts in db_tss:
        test_data.TEST_DB_TIMESTAMPS.append(
            models.DBTimestamp(date=ts['date'],
                               project_count=ts['project_count'],
                               fuzzer_count=ts['fuzzer_count'],
                               function_count=ts['function_count'],
                               function_coverage_estimate=ts['function_coverage_estimate'],
                               accummulated_lines_total=ts['accummulated_lines_total'],
                               accummulated_lines_covered=ts['accummulated_lines_covered']))

    with open(all_functions_file, 'r') as f:
        all_function_list = json.load(f)
    idx = 0
    for func in all_function_list:
        idx += 1
        test_data.TEST_FUNCTIONS.append(
            models.Function(
                name=func['name'],
                project=func['project'],
                runtime_code_coverage=func['runtime_code_coverage'],
                function_filename=func['function_filename'],
                reached_by_fuzzers=0,
                code_coverage_url=func['code_coverage_url'],
                is_reached=func['is_reached'],
                llvm_instruction_count=func['llvm-instruction-count'],
                accummulated_cyclomatic_complexity=func['accumulated_cyclomatic_complexity'],
                undiscovered_complexity=func['undiscovered-complexity']))

    print("Loadded %d functions" % (idx))
    print("Len %d" % (len(test_data.TEST_FUNCTIONS)))

    with open(all_branch_blockers_file, 'r') as f:
        all_branch_blockers = json.load(f)

    for json_bb in all_branch_blockers:
        test_data.TEST_BLOCKERS.append(
                models.BranchBlocker(
                    project_name = json_bb.get('project', ''),
                    function_name = json_bb.get('function-name', ''),
                    unique_blocked_coverage = json_bb.get('blocked-runtime-coverage')))

    with open(project_timestamps_file, 'r') as f:
        project_timestamps_json = json.load(f)
    for project_timestamp in project_timestamps_json:
        test_data.TEST_PROJECT_TIMESTAMPS.append(
            models.ProjectTimestamp(
                date=project_timestamp['date'],
                project_name=project_timestamp['project_name'],
                language=project_timestamp['language'],
                coverage_data=project_timestamp['coverage-data'],
                introspector_data=project_timestamp['introspector-data']))

    # Load all profiles
    with open(project_currents, 'r') as f:
        project_currents_json = json.load(f)
    for project_timestamp in project_currents_json:
        test_data.TEST_PROJECTS.append(
            models.Project(
                name=project_timestamp['project_name'],
                language=project_timestamp.get('language', 'c'),
                date=project_timestamp['date'],
                coverage_data=project_timestamp['coverage-data'],
                introspector_data=project_timestamp['introspector-data']
        ))

    if os.path.isfile(projects_build_status):
        # Read the builds
        with open(projects_build_status, 'r') as f:
            build_json = json.load(f)

        for project_name in build_json:
            project_dict = build_json[project_name]

            test_data.TEST_BUILD_STATUS.append(
                models.BuildStatus(
                    project_name=project_name,
                    fuzz_build_status=project_dict['fuzz-build'],
                    coverage_build_status=project_dict['cov-build'],
                    introspector_build_status=project_dict['introspector-build'],
                    language=project_dict['language'],
                    introspector_build_log = project_dict['introspector-build-log'],
                    coverage_build_log = project_dict['cov-build-log'],
                    fuzz_build_log = project_dict['fuzz-build-log'])
            )

    return
