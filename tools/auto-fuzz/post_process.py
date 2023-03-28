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
import yaml
import json

import argparse
import shutil


def get_result_json(dirname):
    """Reads the result.json from a possible target dir."""
    result_path = os.path.join(dirname, "result.json")
    if not os.path.isfile(result_path):
        return None
    with open(result_path, "r") as result_file:
        result = json.load(result_file)
    return result


# "imports_to_add": ["import markdown_it"], "exceptions_to_handle": ["KeyError"],
def get_exceptions(dirname):
    result = get_result_json(dirname)
    if result is None:
        return []
    return result.get('exceptions_to_handle')


def get_imports(dirname):
    result = get_result_json(dirname)
    if result is None:
        return []
    return result.get('imports_to_add')


def get_function_target(dirname):
    result = get_result_json(dirname)
    if result is None:
        return []
    return result.get('target function')


def get_heuristics_from_trial(dirname):
    result = get_result_json(dirname)
    if result is None:
        return []
    return result.get('heuristics-used')


def get_code_cov_from_trial(dirname):
    """Returns the max edge coverage of a specific OSS-Fuzz run. Return -1
    if the build or run was unsuccessful.
    """
    result = get_result_json(dirname)
    if result is None:
        return None

    if result.get('auto-build') != 'True':
        return None

    # Read coverage log
    oss_fuzz_run_log = os.path.join(dirname, "autofuzz-log",
                                    "oss-fuzz-run.out")
    if not os.path.isfile(oss_fuzz_run_log):
        return None
    with open(oss_fuzz_run_log, "r") as orf:
        oss_run_out = orf.read()

    max_cov = -1
    cov_data = []
    for line in oss_run_out.split("\n"):
        if "cov: " in line:
            line_cov = int(line.split("cov:")[1].lstrip().split(" ")[0])
            cov_data.append(line_cov)

    return cov_data


def interpret_autofuzz_run(dirname: str, only_report_max: bool = False):
    """Reads the results from an autofuzz run on a given project and returns
    a dictionary with various information, e.g. the top trial run.
    """
    # Read config
    proj_yaml_file = os.path.join(dirname, "base-autofuzz", "project.yaml")
    if not os.path.isfile(proj_yaml_file):
        return None, None
    with open(proj_yaml_file, "r") as stream:
        proj_yaml = yaml.safe_load(stream)

    # Go through each of the -idx-X directories
    idx_dir_prefix = "autofuzz-"
    trial_runs = dict()
    for trial_run_dir in os.listdir(dirname):
        if not idx_dir_prefix in trial_run_dir:
            continue

        try:
            idx = int(trial_run_dir.split("-")[-1])
        except:
            continue
        trial_runs[trial_run_dir] = {'max_cov': -2}
        subpath = os.path.join(dirname, trial_run_dir)
        cov_data = get_code_cov_from_trial(subpath)
        if cov_data is None or len(cov_data) < 1:
            max_cov = -1
            min_cov = -1
        else:
            min_cov = cov_data[0]
            max_cov = cov_data[-1]
        trial_runs[trial_run_dir]['max_cov'] = max_cov
        trial_runs[trial_run_dir]['min_cov'] = min_cov
        trial_runs[trial_run_dir]['name'] = trial_run_dir
        trial_runs[trial_run_dir][
            'heuristics-used'] = get_heuristics_from_trial(subpath)
        trial_runs[trial_run_dir]['function-target'] = get_function_target(
            subpath)
        trial_runs[trial_run_dir]['exceptions'] = get_exceptions(subpath)
        trial_runs[trial_run_dir]['imports'] = get_imports(subpath)

    return proj_yaml, trial_runs


def _print_summary_of_trial_run(trial_run,
                                proj_name,
                                autofuzz_project_dir,
                                additional="",
                                print_in_ci=False):
    trial_name = trial_run['name']
    python_fuzz_path = os.path.join(autofuzz_project_dir, trial_run['name'],
                                    "fuzz_1.py")
    jvm_fuzz_path = os.path.join(autofuzz_project_dir, trial_run['name'],
                                 "Fuzz1.java")
    fuzz_path = ""
    if os.path.isfile(python_fuzz_path):
        fuzz_path = python_fuzz_path
    elif os.path.isfile(jvm_fuzz_path):
        fuzz_path = jvm_fuzz_path

    if print_in_ci:
        if len(proj_name) < 50:
            proj_name = proj_name + " " * (50 - len(proj_name))
        if len(trial_name) < 21:
            trial_name = trial_name + " " * (21 - len(trial_name))
        print("%s :: %15s ::  %21s :: [%5s : %5s] :: %s :: %s :: %s" %
              (proj_name, autofuzz_project_dir, trial_name,
               str(trial_run['max_cov']), str(trial_run['min_cov']), fuzz_path,
               trial_run['heuristics-used'], trial_run['function-target']))
    else:
        # Print using space-sepratation between columns.
        print("%s %s %s %s %s %s %s %s %s" %
              (proj_name, autofuzz_project_dir, trial_name,
               str(trial_run['min_cov']), str(trial_run['max_cov']),
               str(trial_run['max_cov'] - trial_run['min_cov']), fuzz_path,
               trial_run['heuristics-used'], trial_run['function-target']))


def get_top_trial_run(trial_runs):
    curr_top = None
    top_dir = None
    for subdir in trial_runs:
        sd = trial_runs[subdir]
        if sd['max_cov'] < 0:
            continue
        if curr_top is None:
            curr_top = sd
            top_dir = subdir
        if sd['max_cov'] > curr_top['max_cov']:
            curr_top = sd
            top_dir = subdir
    return top_dir


def get_cov_ranked_trial_runs(trial_runs):
    ranked_runs = sorted(trial_runs.values(),
                         key=lambda x: x['max_cov'],
                         reverse=True)
    return ranked_runs


def run_on_all_dirs():
    for autofuzz_project_dir in os.listdir("."):
        if "autofuzz-" in autofuzz_project_dir:
            proj_yaml, trial_runs = interpret_autofuzz_run(
                autofuzz_project_dir)
            if proj_yaml is None:
                continue
            if len(trial_runs) == 0:
                continue
            top_run = get_top_trial_run(trial_runs)
            if top_run is None:
                continue
            _print_summary_of_trial_run(trial_runs[top_run],
                                        proj_yaml['main_repo'],
                                        autofuzz_project_dir)


def heuristics_summary():
    """Print for each heuristic the resulting code coverage achieved."""
    all_runs = []
    for autofuzz_project_dir in os.listdir("."):
        if "autofuzz-" in autofuzz_project_dir:
            proj_yaml, trial_runs = interpret_autofuzz_run(
                autofuzz_project_dir)
            if proj_yaml is None:
                continue
            if len(trial_runs) == 0:
                continue
            for trial_run in trial_runs:
                all_runs.append((proj_yaml, trial_runs[trial_run]))

    heuristics_dict = dict()
    for proj_yaml, trial_run in all_runs:
        heuristics = ",".join(trial_run.get('heuristics-used'))
        if heuristics not in heuristics_dict:
            heuristics_dict[heuristics] = dict()
        if not trial_run['max_cov'] in heuristics_dict[heuristics]:
            heuristics_dict[heuristics][trial_run['max_cov']] = list()

        heuristics_dict[heuristics][trial_run['max_cov']].append(trial_run)

    for hrst in heuristics_dict:
        print("Heuristic: %s" % (hrst))
        cov_list = []
        for cov in heuristics_dict[hrst]:
            cov_list.append((cov, len(heuristics_dict[hrst][cov])))
        for cov, count in sorted(cov_list, key=lambda x: x[1], reverse=True):
            print("  cov: %d :: %d" % (cov, count))


def extract_ranked(target_dir, runs_to_rank=20):
    proj_yaml, trial_runs = interpret_autofuzz_run(target_dir)
    if proj_yaml is None:
        return None
    if len(trial_runs) == 0:
        return None
    ranked_runs = get_cov_ranked_trial_runs(trial_runs)

    success_runs = []
    for i in range(min(runs_to_rank, len(ranked_runs))):
        trial_run = ranked_runs[i]
        if trial_run['max_cov'] <= 0:
            continue
        success_runs.append(trial_run)

        _print_summary_of_trial_run(trial_run, proj_yaml['main_repo'],
                                    target_dir)
    return success_runs


def get_cmdline_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest='command')

    all_parser = subparsers.add_parser(
        'all', help="Gets the max performer in all auto-fuzz runs.")

    run_parser = subparsers.add_parser(
        'run', help="Handles activities with respect to individual runs")
    run_parser.add_argument("dir", type=str)
    run_parser.add_argument("--to-rank", type=int, default=20)

    heuristics_parser = subparsers.add_parser(
        'heuristics-summary',
        help=
        "Shows summary of how each heuristic performed with respect to all auto-fuzz modules"
    )

    merge_parser = subparsers.add_parser(
        'merge', help="Merge all fuzzers from one run into one project")
    merge_parser.add_argument("dir", type=str)

    return parser


def _get_next_merged_dir(base_dir):
    AUTO_MERGE = "auto-merged-"
    max_idx = -1
    for dirname in os.listdir(base_dir):
        try:
            idx = int(dirname.replace(AUTO_MERGE, ""))
            if idx > max_idx:
                max_idx = idx
        except:
            pass
    return os.path.join(base_dir, AUTO_MERGE + str(max_idx + 1))


def _merge_runs(trial_dir, successful_runs):
    """Wraps a list of successful runs into a single directory.
    Returns the directory name of the merged directory.
    """
    next_merged_dir = _get_next_merged_dir(os.getcwd())
    os.mkdir(next_merged_dir)

    print("Working directory: %s" % (next_merged_dir))
    idx = 0
    for run in successful_runs:
        print(os.path.join(trial_dir, run['name']))

        # Copy over the fuzzer
        src_file = os.path.join(trial_dir, run['name'], "fuzz_1.py")
        dst_file = os.path.join(next_merged_dir, "fuzz_%d.py" % (idx))
        idx += 1
        shutil.copyfile(src_file, dst_file)

    # Copy over some base dfiles
    base_autofuzz = os.path.join(trial_dir, "base-autofuzz")
    build_file = os.path.join(base_autofuzz, "build.sh")
    shutil.copy(build_file, next_merged_dir)
    docker_file = os.path.join(base_autofuzz, "Dockerfile")
    shutil.copy(docker_file, next_merged_dir)
    project_yaml = os.path.join(base_autofuzz, "project.yaml")
    shutil.copy(project_yaml, next_merged_dir)

    for ld in os.listdir(base_autofuzz):
        if os.path.isdir(os.path.join(base_autofuzz, ld)) and ld != "work":
            # This is likely the folder containing the source code of the
            # project. Copy this over.
            shutil.copytree(os.path.join(base_autofuzz, ld),
                            os.path.join(next_merged_dir, ld))
    return next_merged_dir


def merge_run(target_directory):
    print("Merging run")
    # Get all succcessful directories in target module
    proj_yaml, trial_runs = interpret_autofuzz_run(target_directory)
    if proj_yaml is None:
        print("Found no project.yaml files. Will not perform merge.")
        return None
    if len(trial_runs) == 0:
        print("Found no trial runs. Will not perform merge.")
        return None
    ranked_runs = get_cov_ranked_trial_runs(trial_runs)
    successful_runs = [run for run in ranked_runs if run['max_cov'] > 0]

    if len(successful_runs) == 0:
        print("Found no successful runs. Will not perform merge.")
        return None

    print("Merging %d runs" % (len(successful_runs)))
    merged_project_dir = _merge_runs(target_directory, successful_runs)
    return merged_project_dir


def main():
    parser = get_cmdline_parser()
    args = parser.parse_args()

    if args.command == 'all':
        run_on_all_dirs()
    elif args.command == 'run':
        extract_ranked(args.dir, args.to_rank)
    elif args.command == 'heuristics-summary':
        heuristics_summary()
    elif args.command == "merge":
        merge_run(args.dir)


if __name__ == "__main__":
    main()
