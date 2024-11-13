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

def run_rust_analysis(target_directory: str) -> List[Dict]:
    """Run the Rust analysis tool and retrieve JSON results."""
    try:
        result = subprocess.run(
            ['cargo', 'run', '--', target_directory],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd='rust_function_analyser',
            text=True,
            check=True
        )
        return json.loads(result.stdout)
    except subprocess.CalledProcessError:
        return []
    except ValueError:
        return []

def create_yaml_output(data: List[Dict], output_file='data.yaml'):
    """Generate a YAML file with the analysis results."""
    yaml_data = {
        'Fuzzer filename': '',
        'All functions': {
            'Function list name': 'All functions',
            'Elements': []
        }
    }

    for func in data:
        yaml_data['All functions']['Elements'].append({
            'functionName': func['name'],
            'functionSourceFile': func['file'],
            'linkageType': '',
            'functionLinenumber': func.get('start_line', 0),
            'functionLinenumberEnd': func.get('end_line', 0),
            'functionDepth': func['depth'],
            'returnType': func['return_type'],
            'argCount': func['arg_count'],
            'argTypes': func['arg_types'],
            'constantsTouched': [],
            'argNames': [],
            'BBCount': func['bbcount'],
            'iCount': func['icount'],
            'EdgeCount': func['edge_count'],
            'CyclomaticComplexity': func['complexity'],
            'functionsReached': func['called_functions'],
            'functionUses': func['function_uses'],
            'BranchProfiles': func['branch_profiles'],
            'Callsites': []
        })

    with open(output_file, 'w') as file:
        yaml.dump(yaml_data, file, default_flow_style=False)

    print(f'YAML output saved to {output_file}')

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('Usage: python3 script.py <target_directory>')
        sys.exit(1)

    target_dir = sys.argv[1]
    if not Path(target_dir).is_dir():
        print(f'Error: {target_dir} is not a valid directory')
        sys.exit(1)

    # Run the rust analysis frontend code
    rust_analysis_results = run_rust_analysis(target_dir)

    create_yaml_output(rust_analysis_results)
