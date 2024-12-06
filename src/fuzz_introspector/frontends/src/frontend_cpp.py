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
#
################################################################################

import os
import pathlib
import logging

from tree_sitter import Language, Parser
import tree_sitter_cpp

tree_sitter_languages = {'cpp': Language(tree_sitter_cpp.language())}

language_parsers = {'cpp': Parser(Language(tree_sitter_cpp.language()))}

logger = logging.getLogger(name=__name__)
LOG_FMT = '%(asctime)s.%(msecs)03d %(levelname)s %(module)s - %(funcName)s: %(message)s'


class Project():
    """Wrapper for doing analysis of a collection of source files."""

    def __init__(self, source_code_files):
        self.source_code_files = source_code_files

    def get_source_codes_with_harnesses(self):
        """Gets the source codes that holds libfuzzer harnesses."""
        harnesses = []
        for source_code in self.source_code_files:
            logger.info('Checking: %s'%(source_code.source_file))
            if source_code.has_libfuzzer_harness():
                harnesses.append(source_code)
        return harnesses

    def extract_calltree(self,
                         source_code=None,
                         function=None,
                         visited_functions=None,
                         depth=0,
                         line_number=-1):
        """Extracts calltree string of a calltree so that FI core can use it."""
        # Create calltree from a given function
        # Find the function in the source code
        if not visited_functions:
            visited_functions = set()

        if not function:
            return ''

        line_to_print = '  ' * depth
        line_to_print += function
        line_to_print += ' '

        if not source_code:
            source_code = self.find_source_with_func_def(function)
        if source_code:
            line_to_print += source_code.source_file

        line_to_print += ' '
        line_to_print += str(line_number)

        line_to_print += '\n'
        if not source_code:
            return line_to_print

        func = source_code.get_function_node(function)
        callsites = func.callsites()

        if function in visited_functions:
            return line_to_print

        visited_functions.add(function)
        for cs, byte_range in callsites:
            line_number = source_code.get_linenumber(byte_range[0])
            line_to_print += self.extract_calltree(
                function=cs,
                visited_functions=visited_functions,
                depth=depth + 1,
                line_number=line_number)
        return line_to_print

    def find_source_with_func_def(self, target_function_name):
        """Finds the source code with a given function."""
        source_codes_with_target = []
        for source_code in self.source_code_files:
            if source_code.has_function_definition(target_function_name):
                source_codes_with_target.append(source_code)

        if len(source_codes_with_target) == 1:
            # We hav have, in this case it's trivial.
            return source_codes_with_target[0]

        return None


class SourceCodeFile():
    """Class for holding file-specific information."""

    def __init__(self, source_file, language, source_content=""):
        self.source_file = source_file
        self.language = language
        self.parser = language_parsers.get(self.language)
        self.tree_sitter_lang = tree_sitter_languages[self.language]

        self.root = None
        self.function_names = []
        self.line_range_pairs = []
        self.struct_defs = []
        self.typedefs = []
        self.includes = set()

        if source_content:
            self.source_content = source_content
        else:
            with open(self.source_file, 'rb') as f:
                self.source_content = f.read()

        # List of function definitions in the source file.
        self.func_defs = []

        # Initialization ruotines
        self.load_tree()

        # Load function definitions
        self._set_function_defintions()
        # self.extract_types()

    def get_function_node(self, target_function_name):
        """Gets the tree-sitter node corresponding to a function."""

        # Find the first instance of the function name
        for func in self.func_defs:
            if func.name() == target_function_name:
                return func
        return None
    
    def has_function_definition(self, target_function_name):
        """Returns if the source file holds a given function definition."""

        for func in self.func_defs:
            if func.name() == target_function_name:
                return True
        return False

    def load_tree(self) -> None:
        """Load the the source code into a treesitter tree, and set
        the root node."""
        if self.language == 'cpp' and not self.root:
            self.root = self.parser.parse(self.source_content).root_node

    def has_libfuzzer_harness(self) -> bool:
        """Returns whether the source code holds a libfuzzer harness"""
        for func in self.func_defs:
            if 'LLVMFuzzerTestOneInput' in func.name():
                return True

        return False

    def _set_function_defintions(self):
        logger.info('Extracting definitions')
        func_def_query_str = '( function_definition ) @fd '
        func_def_query = self.tree_sitter_lang.query(func_def_query_str)

        function_res = func_def_query.captures(self.root)
        for _, funcs in function_res.items():
            for func in funcs:
                self.func_defs.append(
                    FunctionDefinition(func, self.tree_sitter_lang, self))

    def get_linenumber(self, bytepos):
        """Gets the line number corresponding to a byte range."""

        # TODO(David): fix up encoding issues.
        if not self.line_range_pairs:
            source_content = self.source_content.decode()
            payload_range = 1
            for line in source_content.split('\n'):
                end_line_pos = payload_range + len(line) + 1
                self.line_range_pairs.append((payload_range, end_line_pos))
                payload_range = end_line_pos

        lineno = 1
        for start, end in self.line_range_pairs:
            if bytepos >= start and bytepos <= end:
                return lineno
            lineno += 1

        return -1

class FunctionDefinition():
    """Wrapper for a function definition"""

    def __init__(self, root, tree_sitter_lang, source_code):
        self.root = root
        self.tree_sitter_lang = tree_sitter_lang
        self.parent_source = source_code

        logger.info(self.name())

    def name(self):
        """Gets name of a function"""
        function_name = ''
        name_node = self.root
        while name_node.child_by_field_name('declarator') is not None:
            name_node = name_node.child_by_field_name('declarator')
            # Assign function name here because we want to make sure that there is a
            # declarator when defining the name.
            function_name = name_node.text.decode()
        return function_name


    def callsites(self):
        """Gets the callsites of the function."""
        callsites = []
        call_query = self.tree_sitter_lang.query('( call_expression ) @ce')
        call_res = call_query.captures(self.root)
        for _, call_exprs in call_res.items():
            for call_expr in call_exprs:
                for call_child in call_expr.children:
                    if call_child.type == 'identifier':
                        callsites.append(
                            (call_child.text.decode(), call_child.byte_range))
        # Sort the callsites relative to their end position. End position
        # here makes sense to handle cases of e.g.
        # func1(func2(), func3())
        # where the execution ordering is func2 -> func3 -> func1
        callsites = list(sorted(callsites, key=lambda x: x[1][1]))

        return callsites


def capture_source_files_in_tree(directory_tree, language):
    """Captures source code files in a given directory."""
    language_extensions = {'cpp': ['.cpp', '.cc', '.c++', '.h']}
    language_files = []
    for dirpath, _dirnames, filenames in os.walk(directory_tree):
        for filename in filenames:
            if any([ext for ext in language_extensions[language] if pathlib.Path(filename).suffix in ext]):
                language_files.append(os.path.join(dirpath, filename))
    return language_files

def load_treesitter_trees(source_files, log_harnesses=True):
    """Creates treesitter trees for all files in a given list of source files."""
    results = []

    for language in source_files:
        if language == 'cpp':
            for code_file in source_files[language]:
                source_cls = SourceCodeFile(code_file, language)
                if log_harnesses:
                    if source_cls.has_libfuzzer_harness():
                        logger.info('harness: %s', code_file)
                results.append(source_cls)
    return results