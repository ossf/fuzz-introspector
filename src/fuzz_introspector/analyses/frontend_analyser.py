# Copyright 2025 Fuzz Introspector Authors
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
"""Analysis plugin for analysing test files."""
import json
import logging
import os

from typing import (Any, List, Dict, Optional)

from fuzz_introspector import (analysis, html_helpers, utils)

from fuzz_introspector.datatypes import (project_profile, fuzzer_profile)

from fuzz_introspector.frontends import oss_fuzz

from tree_sitter import Language, Parser, Query
import tree_sitter_cpp

logger = logging.getLogger(name=__name__)

QUERY = """
(declaration type: (_) @dt declarator: (pointer_declarator declarator: (identifier) @dn)) @dp

(declaration type: (_) @dt declarator: (array_declarator declarator: (identifier) @dn)) @da

(declaration type: (_) @dt declarator: (identifier) @dn) @d

(assignment_expression left: (identifier) @an
 right: (call_expression function: (identifier) @ai)) @ae

(call_expression function: (identifier) @cn arguments: (argument_list) @ca)
"""

PRIMITIVE_TYPES = [
    'void', 'auto', '_Bool', 'bool', 'byte', 'char', 'char16_t', 'char32_t',
    'char8_t', 'complex128', 'complex64', 'double', 'f32', 'f64', 'float',
    'float32', 'float64', 'i8', 'i16', 'i32', 'i64', 'i128', 'int', 'int8',
    'int16', 'int32', 'int64', 'isize', 'long', 'double', 'nullptr_t', 'rune',
    'short', 'str', 'string', 'u8', 'u16', 'u32', 'u64', 'u128', 'uint',
    'uint8', 'uint16', 'uint32', 'uint64', 'usize', 'uintptr', 'unsafe.Pointer',
    'wchar_t', 'size_t'
]


class FrontendAnalyser(analysis.AnalysisInterface):
    """Analysis utility for a second frontend run and test file analysis."""
    # TODO arthur extend to other language
    LANGUAGE: dict[str, Language] = {
        'c-cpp': Language(tree_sitter_cpp.language()),
    }

    name: str = 'FrontendAnalyser'

    def __init__(self) -> None:
        self.json_results: Dict[str, Any] = {}
        self.json_string_result = ''
        self.language = ''
        self.directory = set()
        if os.path.isdir('/src/'):
            self.directory.add('/src/')

    def _check_primitive(self, type_str: Optional[str]) -> bool:
        """Check if the type str is primitive."""
        if not type_str:
            return True

        type_str = type_str.replace('*', '').replace('[]', '')

        return type_str in PRIMITIVE_TYPES

    @classmethod
    def get_name(cls):
        """Return the analyser identifying name for processing.

        :return: The identifying name of this analyser
        :rtype: str
        """
        return cls.name

    def get_json_string_result(self) -> str:
        """Return the stored json string result.

        :return: The json string result processed and stored
            by this analyser
        :rtype: str
        """
        if self.json_string_result:
            return self.json_string_result

        return json.dumps(self.json_results)

    def set_json_string_result(self, json_string: str):
        """Store the result of this analyser as json string result
        for further processing in a later time.

        :param json_string: A json string variable storing the
            processing result of the analyser for future use
        :type json_string: str
        """
        self.json_string_result = json_string

    def set_base_information(self, directory: str, language: str):
        """Setter for base information."""
        self.directory.add(os.path.abspath(directory))
        self.language = language

    def analysis_func(self,
                      table_of_contents: html_helpers.HtmlTableOfContents,
                      tables: List[str],
                      proj_profile: project_profile.MergedProjectProfile,
                      profiles: List[fuzzer_profile.FuzzerProfile],
                      basefolder: str, coverage_url: str,
                      conclusions: List[html_helpers.HTMLConclusion],
                      out_dir: str) -> str:
        """Analysis function. Perform another frontend run and extract all
        test files in the project for additional analysis."""
        # Configure base directory and detect language
        basefolder = os.environ.get('SRC', '/src')
        language = utils.detect_language(basefolder)

        # Prepare separate out directory
        temp_dir = os.path.join(out_dir, 'second-frontend-run')
        os.makedirs(temp_dir, exist_ok=True)

        # Perform a second run of the frontend on the target project. This
        # ensure non-compiled source codes ignored by LTO are also included
        # in the analysis.
        oss_fuzz.analyse_folder(language=language,
                                directory=basefolder,
                                out=temp_dir,
                                module_only=True)

        # Generate FI backend analysis report from second frontend run result
        introspection_proj = analysis.IntrospectionProject(
            proj_profile.language, basefolder, temp_dir)
        introspection_proj.load_data_files(True, temp_dir, basefolder)

        # Calls standalone analysis
        self.standalone_analysis(introspection_proj.proj_profile,
                                 introspection_proj.profiles, out_dir)

        return ''

    def standalone_analysis(self,
                            proj_profile: project_profile.MergedProjectProfile,
                            profiles: List[fuzzer_profile.FuzzerProfile],
                            out_dir: str) -> None:
        """Standalone analysis."""
        super().standalone_analysis(proj_profile, profiles, out_dir)

        # Extract all functions
        functions = []
        for profile in profiles:
            functions.extend(profile.all_class_functions.values())
        func_names = [f.function_name.split('::')[-1] for f in functions]

        # Get test files from json
        test_files = set()
        if os.path.isfile(os.path.join(out_dir, 'all_tests.json')):
            with open(os.path.join(out_dir, 'all_tests.json'), 'r') as f:
                test_files = set(json.load(f))

        # Auto determine base information if not provided
        if not self.directory:
            paths = [
                os.path.abspath(func.function_source_file)
                for func in functions
            ]
            common_path = os.path.commonpath(paths)
            if os.path.isfile(common_path):
                common_path = os.path.dirname(common_path)
            self.directory.add(common_path)

        if not self.language:
            self.language = proj_profile.language

        # Ensure all test/example files has been added
        test_files.update(
            analysis.extract_tests_from_directories(self.directory,
                                                    self.language, out_dir,
                                                    False))

        tree_sitter_lang = self.LANGUAGE.get(self.language)
        if not tree_sitter_lang:
            logger.warning('Language not support: %s', self.language)
            return None

        # Extract calls from each test/example file
        test_functions: dict[str, list[dict[str, object]]] = {}
        parser = Parser(tree_sitter_lang)
        query = Query(tree_sitter_lang, QUERY)
        for test_file in test_files:
            func_call_list = []
            handled = []

            # Tree sitter parsing of the test filees
            node = None
            if os.path.isfile(test_file):
                with open(test_file, 'rb') as f:
                    node = parser.parse(f.read()).root_node

            if not node:
                continue

            # Extract function calls data from test files
            data = query.captures(node)

            # Extract variable declarations (normal, pointers, arrays)
            declarations = {}
            type_nodes = data.get('dt', [])
            name_nodes = data.get('dn', [])
            kinds = {
                (n.start_point[0], n.start_point[1]): kind
                for kind in ('dp', 'da', 'dp')
                for n in data.get(kind, [])
            }

            # Process variable declarations
            for name_node, type_node in zip(name_nodes, type_nodes):
                if not name_node.text or not type_node.text:
                    continue

                name = name_node.text.decode(encoding='utf-8',
                                             errors='ignore').strip()
                base = type_node.text.decode(encoding='utf-8',
                                             errors='ignore').strip()

                pos = (name_node.start_point[0], name_node.start_point[1])
                kind = kinds.get(pos, 'dp')

                if kind == 'dp':
                    full_type = f'{base}*'
                elif kind == 'da':
                    full_type = f'{base}[]'
                else:
                    full_type = base

                declarations[name] = {
                    'type': full_type,
                    'decl_line': pos[0] + 1,
                    'init_func': None,
                    'init_start': -1,
                    'init_end': -1,
                }

            # Extract and process variable initialisation and assignment
            assign_names = data.get('an', [])
            assign_inits = data.get('ai', [])
            for name_node, stmt_node in zip(assign_names, assign_inits):
                if not name_node.text or not stmt_node.text:
                    continue

                name = name_node.text.decode(encoding='utf-8',
                                             errors='ignore').strip()
                stmt = stmt_node.text.decode(encoding='utf-8',
                                             errors='ignore').strip()

                pos = (stmt_node.start_point[0], stmt_node.end_point[0])
                if name in declarations:
                    declarations[name]['init_func'] = stmt
                    declarations[name]['init_start'] = pos[0] + 1
                    declarations[name]['init_end'] = pos[1] + 1

            # Capture function called and args by this test files
            call_names = data.get('cn', [])
            call_args = data.get('ca', [])
            for name_node, args_node in zip(call_names, call_args):
                if not name_node.text:
                    continue

                name = name_node.text.decode(encoding='utf-8',
                                             errors='ignore').strip()

                # Skip non-project functions
                if name not in func_names:
                    continue

                # Extract declaration and intialisation for params
                # of this function call
                params = set()
                for child in args_node.children:
                    stack = [child]
                    while stack:
                        curr = stack.pop()

                        if curr.type == 'identifier' and curr.text:
                            params.add(
                                curr.text.decode(encoding='utf-8',
                                                 errors='ignore').strip())
                            break
                        if curr.child_count > 0:
                            stack.extend(curr.children)

                # Filter declaration for this function call and store full
                # details including declaration initialisation of parameters
                # used for this function call
                filtered = [
                    decl for param, decl in declarations.items()
                    if param in params and
                    not self._check_primitive(decl.get('type', 'void'))
                ]
                key = (name, name_node.start_point[0], name_node.end_point[0])
                if key in handled:
                    continue

                handled.append(key)
                func_call_list.append({
                    'function_name': name,
                    'params': filtered,
                    'call_start': name_node.start_point[0] + 1,
                    'call_end': name_node.end_point[0] + 1,
                })

            func_call_list = [call for call in func_call_list if call['params']]
            if func_call_list:
                test_functions[test_file] = func_call_list

        # Store test files
        with open(os.path.join(out_dir, 'all_tests.json'), 'w') as f:
            f.write(json.dumps(list(test_files)))

        # Store test files with cross reference information
        with open(os.path.join(out_dir, 'all_tests_with_xreference.json'),
                  'w') as f:
            f.write(json.dumps(test_functions))

        return None
