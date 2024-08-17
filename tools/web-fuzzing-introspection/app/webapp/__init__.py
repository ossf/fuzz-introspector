import os
import json

from typing import Dict, List, Any
from . import data_storage, models


def load_db() -> None:
    """Loads the database"""
    print("Loading db")

    db_timestamps_file = os.path.join(
        os.path.dirname(__file__), "../static/assets/db/db-timestamps.json")
    project_timestamps_file = os.path.join(
        os.path.dirname(__file__),
        "../static/assets/db/all-project-timestamps.json")
    project_currents = os.path.join(
        os.path.dirname(__file__),
        "../static/assets/db/all-project-current.json")

    projects_build_status = os.path.join(
        os.path.dirname(__file__), "../static/assets/db/build-status.json")
    all_header_files_file = os.path.join(
        os.path.dirname(__file__), "../static/assets/db/all-header-files.json")

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
                fuzzer_count=project_timestamp['fuzzer-count'],
                introspector_url=project_timestamp.get('introspector_url',
                                                       None),
                project_url=project_timestamp.get('project_url', None)))
    # If we're caching, then remove the timestamp file.
    force_cache = True
    if 'G_ANALYTICS_TAG' in os.environ or force_cache:
        os.remove(project_timestamps_file)

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
                fuzzer_count=project_timestamp['fuzzer-count'],
                project_repository=project_timestamp['project_repository']))

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

    if os.path.isfile(all_header_files_file):
        with open(all_header_files_file, 'r') as f:
            all_header_files = json.load(f)
        data_storage.ALL_HEADER_FILES = all_header_files

    # Load all functions into a cache
    data_storage.load_cache()

    return
