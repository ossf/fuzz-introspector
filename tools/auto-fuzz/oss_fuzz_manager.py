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

import os
import sys
import shutil
import subprocess


def run(cmd):
    # Set stdin to NULL to avoid messing up the terminal.
    proc = subprocess.Popen(cmd,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            stdin=subprocess.DEVNULL)
    stdout, stderr = proc.communicate()

    return proc.returncode, stdout, stderr


def check_if_proj_runs(oss_fuzz_base, proj_name, fuzz_name, log_dir):
    curr_dir = os.getcwd()
    cmd = [
        "python3",
        os.path.join(oss_fuzz_base, "infra/helper.py"), "run_fuzzer",
        proj_name, fuzz_name, "--", "-max_total_time=10"
    ]
    code, out, err = run(cmd)

    # Write all logs
    out_log = os.path.join(log_dir, "oss-fuzz-run.out")
    err_log = os.path.join(log_dir, "oss-fuzz-run.err")
    with open(out_log, "wb") as f:
        f.write(out)
    with open(err_log, "wb") as f:
        f.write(err)


def copy_and_introspect_project(src_folder, oss_fuzz_base, log_dir=None):
    """Copies src_folder into the oss-fuzz located at oss_fuzz_base project's
    folder and runs the oss-fuzz command:
    introspect

    Returns True.
    """
    project_name = os.path.basename(src_folder)

    # Copy the directory
    dst_project_folder = os.path.join(oss_fuzz_base, "projects", project_name)
    if os.path.isdir(dst_project_folder):
        shutil.rmtree(dst_project_folder)
    shutil.copytree(src_folder, dst_project_folder)

    cmd = [
        "python3",
        os.path.join(oss_fuzz_base, "infra/helper.py"), "introspector",
        project_name, "--seconds=20"
    ]
    code, out, err = run(cmd)
    # Write build output to log diretory.
    out_log = os.path.join(log_dir, "oss-fuzz.out")
    err_log = os.path.join(log_dir, "oss-fuzz.err")
    with open(out_log, "wb") as f:
        f.write(out)
    with open(err_log, "wb") as f:
        f.write(err)
    return True


def copy_and_build_project(src_folder,
                           oss_fuzz_base,
                           log_dir=None,
                           base_autofuzz=False):
    """Copies src_folder into the oss-fuzz located at oss_fuzz_base project's
    folder and runs the oss-fuzz command:
    build_fuzzers

    Returns True if the build passed. False otherwise.
    """
    project_name = os.path.basename(src_folder)

    # Copy the directory
    dst_project_folder = os.path.join(oss_fuzz_base, "projects", project_name)
    if os.path.isdir(dst_project_folder):
        shutil.rmtree(dst_project_folder)

    try:
        shutil.copytree(src_folder, dst_project_folder)
    except shutil.Error:
        # Bail out if an error occurred.
        return False

    cmd = [
        "python3",
        os.path.join(oss_fuzz_base, "infra/helper.py"), "build_fuzzers",
        project_name
    ]
    code, out, err = run(cmd)
    # Write build output to log diretory.
    out_log = os.path.join(log_dir, "oss-fuzz.out")
    err_log = os.path.join(log_dir, "oss-fuzz.err")
    with open(out_log, "wb") as f:
        f.write(out)
    with open(err_log, "wb") as f:
        f.write(err)

    if base_autofuzz:
        try:
            shutil.rmtree(
                os.path.join(oss_fuzz_base, "projects", "base-autofuzz"))
            cleanup_project("base-autofuzz", oss_fuzz_base)
        except shutil.Error:
            # Pass if base_autofuzz cleaning is failed
            pass

    if b"Building fuzzers failed" in err:
        return False
    else:
        return True


def cleanup_project(proj_name, oss_fuzz_base):
    """Remove everything in the /out/ folder of a project. Does this by calling
    docker run in the same way that OSS-Fuzz handles its Docker images."""
    project_out = os.path.join(oss_fuzz_base, "build", "out", proj_name)
    oss_fuzz_project_docker_args = [
        '-v', f'{project_out}:/out', '-t', f'gcr.io/oss-fuzz/{proj_name}',
        '/bin/bash', '-c', 'rm -rf /out/*'
    ]
    oss_fuzz_docker_cmd = [
        'docker', 'run', '--rm', '--privileged', '--shm-size=2g', '--platform',
        'linux/amd64'
    ]

    oss_fuzz_docker_cmd.extend(oss_fuzz_project_docker_args)
    try:
        subprocess.check_call(oss_fuzz_docker_cmd)
    except subprocess.CalledProcessError:
        pass

    # Remove the OSS-Fuzz docker image itself
    oss_fuzz_docker_tag = f'gcr.io/oss-fuzz/{proj_name}'
    try:
        subprocess.check_call(['docker', 'rmi', oss_fuzz_docker_tag],
                              stderr=subprocess.DEVNULL,
                              stdout=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        pass
    return True
