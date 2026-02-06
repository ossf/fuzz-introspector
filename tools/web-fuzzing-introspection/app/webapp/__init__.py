import json
import logging
import os

from . import data_storage, models

logger = logging.getLogger(__name__)


def load_db() -> None:
    """Loads the database"""
    logger.info("Loading db")

    db_dir = data_storage.DB_DIR
    db_timestamps_file = os.path.join(db_dir, "db-timestamps.json")
    project_timestamps_file = os.path.join(db_dir,
                                           "all-project-timestamps.json")
    project_currents = os.path.join(db_dir, "all-project-current.json")

    projects_build_status = os.path.join(db_dir, "build-status.json")
    all_header_files_file = os.path.join(db_dir, "all-header-files.json")

    all_projects_not_in_ossfuzz = os.path.join(
        db_dir, "projects-not-in-oss-fuzz.json")

    full_project_count = os.path.join(db_dir,
                                      'full-oss-fuzz-project-count.json')

    if len(data_storage.DB_TIMESTAMPS) > 0:
        return

    if os.path.isfile(full_project_count):
        with open(full_project_count, 'r') as f:
            data_storage.ALL_INTEGRATED_PROJECTS = json.load(f)

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
                project_url=project_timestamp.get('project_url', None),
                project_repository=project_timestamp.get(
                    'project_repository', None)))
    # If we're caching, then remove the timestamp file.
    if 'G_ANALYTICS_TAG' in os.environ:
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
                project_repository=project_timestamp['project_repository'],
                light_analysis=project_timestamp.get('light-introspector', {}),
                recent_results=project_timestamp.get('recent_results'),
            ))

    if 'G_ANALYTICS_TAG' in os.environ:
        os.remove(project_currents)

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

    if os.path.isfile(all_projects_not_in_ossfuzz):
        with open(all_projects_not_in_ossfuzz, 'r') as f:
            projects_not_in_ossfuzz = json.load(f)
        data_storage.PROJECTS_NOT_IN_OSSFUZZ = projects_not_in_ossfuzz

    # Load all functions into a cache
    data_storage.load_cache()
