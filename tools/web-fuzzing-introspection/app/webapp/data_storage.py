from typing import List, Dict, Any, Optional

import logging
import os
import orjson

logger = logging.getLogger(__name__)

from .models import (BranchBlocker, BuildStatus, DBTimestamp, DebugStatus,
                     Function, Project, ProjectTimestamp)

DB_DIR = os.path.join(os.path.dirname(__file__), '../static/assets/db')

all_functions_file = os.path.join(DB_DIR, 'all-functions-db-{PROJ}.json')
all_constructors_file = os.path.join(DB_DIR, 'all-constructors-db-{PROJ}.json')

PROJECT_TIMESTAMPS: List[ProjectTimestamp] = []

DB_TIMESTAMPS: List[DBTimestamp] = []

PROJECTS: List[Project] = []

BLOCKERS: List[BranchBlocker] = []

BUILD_STATUS: List[BuildStatus] = []

ALL_HEADER_FILES: List[Dict[str, Any]] = []

TOTAL_FUNCTION_COUNT = -1

JSON_TO_FUNCTION_CACHE: Dict[str, List[Function]] = {}

PROJECTS_NOT_IN_OSSFUZZ: List[str] = []

ALL_INTEGRATED_PROJECTS: List[Dict[str, Any]] = []


def get_projects() -> List[Project]:
    return PROJECTS


def load_cache():
    for project in PROJECTS:
        get_functions_by_project(project.name)


def get_functions_by_project(proj: str) -> List[Function]:
    return retrieve_functions(proj, False)


def get_constructors_by_project(proj: str) -> List[Function]:
    return retrieve_functions(proj, True)


def get_blockers() -> List[BranchBlocker]:
    return BLOCKERS


def get_build_status() -> List[BuildStatus]:
    return BUILD_STATUS


def get_project_debug_report(project: str) -> Optional[DebugStatus]:
    debug_report_path = os.path.join(
        DB_DIR, f"db-projects/{project}/debug_report.json")
    logger.info("Getting path: %s", debug_report_path)
    if not os.path.isfile(debug_report_path):
        logger.warning("Debug report not found: %s", debug_report_path)
        return None

    with open(debug_report_path, 'r') as f:
        debug_report = orjson.loads(f.read())

    debug_model = DebugStatus(
        project_name=project,
        all_files_in_project=debug_report.get('all_files_in_project', []),
        all_functions_in_project=debug_report.get('all_functions_in_project',
                                                  []),
        all_global_variables=debug_report.get('all_global_variables', []),
        all_types=debug_report.get('all_types', []))
    return debug_model


def get_project_branch_blockers(project: str) -> List[BranchBlocker]:
    branch_blockers_path = os.path.join(
        DB_DIR, f"db-projects/{project}/branch_blockers.json")
    logger.info("Getting path: %s", branch_blockers_path)
    if not os.path.isfile(branch_blockers_path):
        logger.warning("Branch blockers not found: %s", branch_blockers_path)
        return []

    with open(branch_blockers_path, 'r') as f:
        branch_report = orjson.loads(f.read())

    branch_models = []
    for json_bb in branch_report:
        branch_models.append(
            BranchBlocker(project_name=json_bb.get('project', ''),
                          function_name=json_bb.get('function_name', ''),
                          unique_blocked_coverage=json_bb.get(
                              'blocked_runtime_coverage'),
                          source_file=json_bb.get('source_file'),
                          blocked_unique_functions=json_bb.get(
                              'blocked_unique_functions'),
                          src_linenumber=json_bb.get('linenumber')))
    return branch_models


def retrieve_functions(proj: str, is_constructor: bool) -> List[Function]:
    """Retrieve functions or constructors"""
    if is_constructor:
        json_path = all_constructors_file.replace('{PROJ}', proj)
    else:
        json_path = all_functions_file.replace('{PROJ}', proj)

    if json_path in JSON_TO_FUNCTION_CACHE:
        return JSON_TO_FUNCTION_CACHE[json_path]

    if os.path.isfile(json_path):
        with open(json_path, 'r') as file:
            function_list = orjson.loads(file.read())
    else:
        return []

    result_list = []
    for func in function_list:
        try:
            debug_argtypes = func['debug']['args']
        except KeyError:
            debug_argtypes = []

        if is_constructor:
            # Constructors must have a return type of its own class
            func['rtn'] = func['file']

        result_list.append(
            Function(name=func['name'],
                     project=proj,
                     runtime_code_coverage=func['cov'],
                     function_filename=func['file'],
                     reached_by_fuzzers=func['fuzzers'],
                     cov_fuzzers=func.get('cov_fuzzers', []),
                     comb_fuzzers=func.get('comb_fuzzers', []),
                     code_coverage_url=func['cov_url'],
                     is_reached=(len(func['fuzzers']) > 0),
                     llvm_instruction_count=func['icount'],
                     accummulated_cyclomatic_complexity=func['acc_cc'],
                     undiscovered_complexity=func['u-cc'],
                     function_arguments=func['args'],
                     function_debug_arguments=debug_argtypes,
                     return_type=func['rtn'],
                     function_argument_names=func['args-names'],
                     raw_function_name=func.get('raw-name', func['name']),
                     source_line_begin=func.get('src_begin', -1),
                     source_line_end=func.get('src_end', -1),
                     callsites=func.get('callsites', {}),
                     func_signature=func.get('sig', func['name']),
                     debug_data=func.get('debug', {}),
                     is_accessible=func.get('access', True),
                     is_jvm_library=func.get('jvm_lib', False),
                     is_enum_class=func.get('enum', False),
                     is_static=func.get('static', False),
                     need_close=func.get('need_close', False),
                     exceptions=func.get('exc', []),
                     asserts=func.get('asserts', [])))
    JSON_TO_FUNCTION_CACHE[json_path] = result_list

    # At this point if google analytics tag is set it means we are in production, and we should
    # delete the .json file then to save storage.
    if 'G_ANALYTICS_TAG' in os.environ:
        os.remove(json_path)

    return result_list
