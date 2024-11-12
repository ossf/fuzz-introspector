# Copyright 2024 Fuzz Introspector Authors
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

import subprocess
import json
import yaml
import os
import sys
import re
from pathlib import Path
from typing import Dict, List, Tuple

def get_rs_files(project_dir: str) -> List[str]:
    """Recursively find all Rust files in the project directory."""
    rs_files = []
    for root, _, files in os.walk(project_dir):
        for file in files:
            if file.endswith(".rs"):
                rs_files.append(os.path.join(root, file))
    return rs_files

def extract_function_line_info_from_file(file_path: str) -> Dict[Tuple[str, str], Tuple[int, int]]:
    """Extract function names with their start and end line numbers from a Rust file."""
    info = {}
    pattern = re.compile(r"fn\s+(\w+)\s*\(")

    with open(file_path, "r") as f:
        lines = f.readlines()

    curr_func = None
    start = 0

    for i, line in enumerate(lines, 1):
        match = pattern.search(line)
        if match:
            if curr_func:
                info[(curr_func, file_path)] = (start, i - 1)

            curr_func = match.group(1)
            start = i

    if curr_func:
        info[(curr_func, file_path)] = (start, len(lines))

    return info

def analyze_project_functions(project_dir: str) -> Dict[Tuple[str, str], Tuple[int, int]]:
    """Analyze all functions in the Rust project and map their line numbers."""
    all_functions = {}
    rs_files = get_rs_files(project_dir)

    for rs_file in rs_files:
        functions = extract_function_line_info_from_file(rs_file)
        all_functions.update(functions)

    return all_functions

def run_rust_analysis(target_directory: str) -> List[Dict]:
    """Run the Rust analysis tool and retrieve JSON results."""
    try:
        result = subprocess.run(
            ["cargo", "run", "--", target_directory],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd="rust_function_analyser",
            text=True,
            check=True
        )
        return json.loads(result.stdout)
    except subprocess.CalledProcessError:
        return []
    except ValueError:
        return []

def add_line_data(rust_results: List[Dict]):
    """Add line data to functions from rust analysis result."""
    line_info = analyze_project_functions(target_dir)

    for func in rust_results:
        func_key = (func["name"], func["file"])
        if func_key in line_info:
            func["start_line"], func["end_line"] = line_info[func_key]
        else:
            func["start_line"], func["end_line"] = 0, 0
        func["called_functions"] = [f.replace(" ", "") for f in func["called_functions"]]

def create_yaml_output(data: List[Dict], output_file="data.yaml"):
    """Generate a YAML file with the analysis results."""
    yaml_data = {
        "Fuzzer filename": "",
        "All functions": {
            "Function list name": "All functions",
            "Elements": []
        }
    }

    for func in data:
        yaml_data["All functions"]["Elements"].append({
            "functionName": func["name"],
            "functionSourceFile": func["file"],
            "linkageType": "",
            "functionLinenumber": func["start_line"],
            "functionLinenumberEnd": func["end_line"],
            "functionDepth": func["depth"],
            "returnType": func["return_type"],
            "argCount": func["arg_count"],
            "argTypes": func["arg_types"],
            "constantsTouched": [],
            "argNames": [],
            "BBCount": 0,
            "ICount": 0,
            "EdgeCount": 0,
            "CyclomaticComplexity": func["complexity"],
            "functionsReached": func["called_functions"],
            "functionUses": 0,
            "BranchProfiles": [],
            "Callsites": []
        })

    with open(output_file, "w") as file:
        yaml.dump(yaml_data, file, default_flow_style=False)

    print(f"YAML output saved to {output_file}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 script.py <target_directory>")
        sys.exit(1)

    target_dir = sys.argv[1]
    if not Path(target_dir).is_dir():
        print(f"Error: {target_dir} is not a valid directory")
        sys.exit(1)

    # Run the rust analysis frontend code
    rust_analysis_results = run_rust_analysis(target_dir)

    # Manually extract the line info for each function.
    # This is needed because the rust analysis syn AST approach
    # cannot retrieve line number info on stable rust and non-nightly build
    add_line_data(rust_analysis_results)

    create_yaml_output(rust_analysis_results)
