import os
import json

from . import data_storage
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
    project_timestamps_file = os.path.join(
        os.path.dirname(__file__),
        "../static/assets/db/all-project-timestamps.json")
    project_currents = os.path.join(
        os.path.dirname(__file__),
        "../static/assets/db/all-project-current.json")
    projects_build_status = os.path.join(
        os.path.dirname(__file__), "../static/assets/db/build-status.json")

    if len(data_storage.DB_TIMESTAMPS) > 0:
        return

    with open(db_timestamps_file, 'r') as f:
        db_tss = json.load(f)
    for ts in db_tss:
        data_storage.DB_TIMESTAMPS.append(
            models.DBTimestamp(
                date=ts['date'],
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
        data_storage.FUNCTIONS.append(
            models.Function(
                name=func['name'],
                project=func['project'],
                runtime_code_coverage=func['runtime_code_coverage'],
                function_filename=func['function_filename'],
                reached_by_fuzzers=func['reached-by-fuzzers'],
                code_coverage_url=func['code_coverage_url'],
                is_reached=func['is_reached'],
                llvm_instruction_count=func['llvm-instruction-count'],
                accummulated_cyclomatic_complexity=func[
                    'accumulated_cyclomatic_complexity'],
                undiscovered_complexity=func['undiscovered-complexity'],
                function_arguments=func['function-arguments'],
                return_type=func['return-type'],
                function_argument_names=func['function-argument-names'],
                raw_function_name=func['raw-function-name'],
                date_str=func.get('date-str', ''),
                source_line_begin=func.get('source_line_begin', '-1'),
                source_line_end=func.get('source_line_end', '-1'),
                callsites=func.get('callsites', [])))

    print("Loadded %d functions" % (idx))
    print("Len %d" % (len(data_storage.FUNCTIONS)))

    with open(project_timestamps_file, 'r') as f:
        project_timestamps_json = json.load(f)
    for project_timestamp in project_timestamps_json:
        data_storage.PROJECT_TIMESTAMPS.append(
            models.ProjectTimestamp(
                date=project_timestamp['date'],
                project_name=project_timestamp['project_name'],
                language=project_timestamp['language'],
                coverage_data=project_timestamp['coverage-data'],
                introspector_data=project_timestamp['introspector-data'],
                fuzzer_count=project_timestamp['fuzzer-count']))

    # Load all profiles
    with open(project_currents, 'r') as f:
        project_currents_json = json.load(f)

    for project_timestamp in project_currents_json:
        data_storage.PROJECTS.append(
            models.Project(
                name=project_timestamp['project_name'],
                language=project_timestamp.get('language', 'c'),
                date=project_timestamp['date'],
                coverage_data=project_timestamp['coverage-data'],
                introspector_data=project_timestamp['introspector-data'],
                fuzzer_count=project_timestamp['fuzzer-count']))

        introspector_data = project_timestamp.get('introspector-data', None)
        if introspector_data is None:
            debug_report = None
        else:
            debug_report = introspector_data.get('debug_report', None)

        if debug_report is None:
            print("Adding empty %s" % (project_timestamp['project_name']))
            data_storage.PROJECT_DEBUG_DATA.append(
                models.DebugStatus(
                    project_name=project_timestamp['project_name'],
                    all_files_in_project=[],
                    all_functions_in_project=[],
                    all_global_variables=[],
                    all_types=[]))
        else:
            print("Adding non-empty %s" % (project_timestamp['project_name']))
            data_storage.PROJECT_DEBUG_DATA.append(
                models.DebugStatus(
                    project_name=project_timestamp['project_name'],
                    all_files_in_project=debug_report.get(
                        'all_files_in_project', []),
                    all_functions_in_project=debug_report.get(
                        'all_functions_in_project', []),
                    all_global_variables=debug_report.get(
                        'all_global_variables,', []),
                    all_types=debug_report.get('all_types', [])))

    if os.path.isfile(projects_build_status):
        # Read the builds
        with open(projects_build_status, 'r') as f:
            build_json = json.load(f)

        for project_name in build_json:
            project_dict = build_json[project_name]

            data_storage.BUILD_STATUS.append(
                models.BuildStatus(
                    project_name=project_name,
                    fuzz_build_status=project_dict['fuzz-build'],
                    coverage_build_status=project_dict['cov-build'],
                    introspector_build_status=project_dict[
                        'introspector-build'],
                    language=project_dict['language'],
                    introspector_build_log=project_dict[
                        'introspector-build-log'],
                    coverage_build_log=project_dict['cov-build-log'],
                    fuzz_build_log=project_dict['fuzz-build-log']))

    return
