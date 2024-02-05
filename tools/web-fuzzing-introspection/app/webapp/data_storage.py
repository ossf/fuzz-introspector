# Auto-generated
#from app.site.models import *

from typing import List

from .models import *

PROJECT_TIMESTAMPS = []

DB_TIMESTAMPS = []

PROJECTS = []

FUNCTIONS = []

BLOCKERS = []

BUILD_STATUS: List[BuildStatus] = []

PROJECT_DEBUG_DATA = []


def get_projects():
    return PROJECTS


def get_functions():
    return FUNCTIONS


def get_blockers():
    return BLOCKERS


def get_build_status() -> List[BuildStatus]:
    return BUILD_STATUS


def get_debug_data():
    return PROJECT_DEBUG_DATA
