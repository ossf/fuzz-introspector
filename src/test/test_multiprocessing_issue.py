# Copyright 2026 Fuzz Introspector Authors
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
"""Tests related to multiprocessing with FuzzerProfile."""

import logging
import multiprocessing
import os
import sys

import pytest

sys.path.append(os.path.dirname(os.path.realpath(__file__)) + "/../")

from fuzz_introspector.datatypes import fuzzer_profile  # noqa: E402
from test_fuzzer_profile import base_cpp_profile  # noqa: E402

logger = logging.getLogger(name=__name__)


@pytest.fixture
def sample_cfg1():
    """Fixture for a sample (shortened paths) calltree"""
    cfg_str = """Call tree
LLVMFuzzerTestOneInput /src/wuffs/fuzz/c/fuzzlib/fuzzlib.c linenumber=-1
  llvmFuzzerTestOneInput /src/wuffs/fuzz/c/../fuzzlib/fuzzlib.c linenumber=93
    jenkins_hash_u32 /src/wuffs/fuzz/c/std/../fuzzlib/fuzzlib.c linenumber=67
    jenkins_hash_u32 /src/wuffs/fuzz/c/std/../fuzzlib/fuzzlib.c linenumber=68
    wuffs_base__ptr_u8__reader /src/wuffs/fuzz/...-snapshot.c linenumber=72
    fuzz /src/wuffs/fuzz/c/std/bmp_fuzzer.c linenumber=74"""
    return cfg_str


def test_manager_dict_forkawarelocal():
    """Low-level reproduction of the ForkAwareLocal bug.

    ``multiprocessing.Manager().dict()`` proxies lose their
    thread-local connection state after ``fork()`` on Python 3.10.0
    (CPython bug bpo-42963, fixed in 3.10.4).

    On Python 3.10.0 this fails with::

      AttributeError: 'ForkAwareLocal' object has no attribute 'connection'

    On Python 3.10.4+ the test passes because CPython no longer
    clears ``ForkAwareLocal`` after fork.
    """
    manager = multiprocessing.Manager()
    d = manager.dict()

    def worker(rd):
        rd["key"] = "value"

    p = multiprocessing.Process(target=worker, args=(d,))
    p.start()
    p.join()

    crashed = p.exitcode != 0
    lost = "key" not in d

    if crashed or lost:
        msg = []
        if crashed:
            msg.append(f"process crashed (exit code {p.exitcode})")
        if lost:
            msg.append("'key' was not stored in the dict")
        pytest.fail(
            f"SyncManager.dict() + fork() failed: {'. '.join(msg)}. "
            "On Python 3.10.0 this is the ForkAwareLocal bug: "
            "'ForkAwareLocal' object has no attribute 'connection'."
        )


def test_fuzzer_profile_accummulate_via_queue(tmpdir, sample_cfg1):
    """Verify that FuzzerProfile.accummulate_profile works with Queue.

    This is the fix for the ForkAwareLocal bug: using
    ``multiprocessing.Queue`` instead of ``SyncManager.dict()``
    avoids the manager process and the fork-related connection
    issues entirely.
    """
    profile_count = 4
    profiles = [
        base_cpp_profile(tmpdir, sample_cfg1, [])
        for _ in range(profile_count)
    ]

    semaphore = multiprocessing.Semaphore(2)
    queue: multiprocessing.Queue = multiprocessing.Queue()

    jobs = []
    for idx, profile in enumerate(profiles):
        p = multiprocessing.Process(
            target=fuzzer_profile.FuzzerProfile.accummulate_profile,
            args=(profile, str(tmpdir), queue, f"uniq-{idx}",
                  semaphore))
        jobs.append(p)
        p.start()

    for proc in jobs:
        proc.join(timeout=30)

    for proc in jobs:
        if proc.exitcode != 0:
            logger.warning("Process %s exited with code %d", proc.pid,
                           proc.exitcode)

    results = []
    while not queue.empty():
        try:
            _, profile = queue.get_nowait()
            results.append(profile)
        except Exception:
            break

    assert len(results) == profile_count, (
        f"Expected {profile_count} profiles, got {len(results)}. "
        "Check that each child correctly puts (uniq_id, self) into "
        "the Queue."
    )

    for profile in results:
        assert isinstance(profile, fuzzer_profile.FuzzerProfile)
