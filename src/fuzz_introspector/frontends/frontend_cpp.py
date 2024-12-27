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


class Project():
    """Wrapper for doing analysis of a collection of source files."""

    def __init__(self, source_code_files):
        self.source_code_files = source_code_files

    def get_source_codes_with_harnesses(self):
        """Gets the source codes that holds libfuzzer harnesses."""
        harnesses = []
        for source_code in self.source_code_files:
            # logger.info('Checking: %s' % (source_code.source_file))
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
            if source_code.has_function_definition(target_function_name,
                                                   exact=True):
                source_codes_with_target.append(source_code)

        if len(source_codes_with_target) == 1:
            # We hav have, in this case it's trivial.
            return source_codes_with_target[0]

        source_codes_with_target = []
        for source_code in self.source_code_files:
            if source_code.has_function_definition(target_function_name,
                                                   exact=False):
                source_codes_with_target.append(source_code)
        if len(source_codes_with_target) == 1:
            # We hav have, in this case it's trivial.
            return source_codes_with_target[0]
        if len(source_codes_with_target) > 1:
            print("We have more than a single source %s" %
                  (target_function_name))
            for sc in source_codes_with_target:
                print("- %s" % (sc.source_file))
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
        self.namespaces = []

        if source_content:
            self.source_content = source_content
        else:
            with open(self.source_file, 'rb') as f:
                self.source_content = f.read()

        # List of function definitions in the source file.
        self.func_defs = []

        # Initialization ruotines
        self.load_tree()
        self.find_namespaces()

        # Load function definitions
        self._set_function_defintions()

    def find_namespaces(self) -> None:
        """Sets self.namespaces"""
        namespace_query = self.tree_sitter_lang.query(
            '( namespace_definition ) @de')
        namespace_res = namespace_query.captures(self.root)
        for _, namespaces in namespace_res.items():
            for namespace in namespaces:
                # TODO(David) handle anonymous namespaces (no name).
                if not namespace.child_by_field_name('name'):
                    continue

                namespace_name = ''
                if namespace.child_by_field_name(
                        'name').type == 'nested_namespace_specifier':
                    for child in namespace.child_by_field_name(
                            'name').children:
                        if not child.is_named:
                            continue
                        namespace_name += child.text.decode() + '::'
                    if namespace_name.endswith('::'):
                        namespace_name = namespace_name[:-2]

                if namespace.child_by_field_name(
                        'name').type == 'namespace_identifier':
                    logger.info(
                        namespace.child_by_field_name('name').text.decode())
                    namespace_name = namespace.child_by_field_name(
                        'name').text.decode()

                logger.info('Namespace name: %s', namespace_name)
                self.namespaces.append(
                    (namespace_name, namespace.byte_range, namespace))
                # Get namespace
                logger.info(namespace.byte_range)

    def get_function_node(self, target_function_name, exact=False):
        """Gets the tree-sitter node corresponding to a function."""

        # Find the first instance of the function name
        for func in self.func_defs:
            if func.scope() is not None:
                if func.scope() + '::' + func.name() == target_function_name:
                    return func
            else:
                if func.name() == target_function_name:
                    return func

        if exact:
            return None

        for func in self.func_defs:

            if func.name() == target_function_name:
                return func

        for func in self.func_defs:
            if func.name() == target_function_name.split('::')[-1]:
                return func
        return None

    def has_function_definition(self, target_function_name, exact=False):
        """Returns if the source file holds a given function definition."""

        if self.get_function_node(target_function_name, exact):
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

        logger.info('Identified function: %s :: %s :: %s :: (%d,%d)',
                    self.name(), self.parent_source.source_file, self.scope(),
                    self.root.start_point.row, self.root.end_point.row)

    def scope(self):
        if not self.parent_source.namespaces:
            return None

        for ns_name, ns_byte_range, ns in self.parent_source.namespaces:
            if self.root.byte_range[0] > ns_byte_range[
                    0] and self.root.byte_range[1] < ns_byte_range[1]:
                return ns_name
        return None

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

                tmp_node = call_expr.child_by_field_name('function')

                function_call = ''
                # Handle callsites where the scope is not None, e.g.
                # ns1::ns2::func1(...);
                if tmp_node.child_by_field_name('scope'):
                    while tmp_node.child_by_field_name('name') is not None:
                        # TODO(David) handle
                        if tmp_node.child_by_field_name(
                                'name').type == 'identifier':
                            if tmp_node.child_by_field_name('scope'):
                                function_call += tmp_node.child_by_field_name(
                                    'scope').text.decode() + '::'
                            function_call += tmp_node.child_by_field_name(
                                'name').text.decode()
                            break

                        if not tmp_node.child_by_field_name('scope'):
                            logger.info('Missing analysis: %s',
                                        tmp_node.text.decode())
                            function_call = ''
                            break
                        function_call += tmp_node.child_by_field_name(
                            'scope').text.decode() + '::'

                        tmp_node = tmp_node.child_by_field_name('name')
                    if not function_call:
                        continue
                # Handle non-scoped function calls
                if tmp_node.type == 'identifier':
                    function_call = tmp_node.text.decode()

                callsites.append((function_call, call_expr.byte_range))

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
    for dirpath, _, filenames in os.walk(directory_tree):
        for filename in filenames:
            if any([
                    ext for ext in language_extensions[language]
                    if pathlib.Path(filename).suffix in ext
            ]):
                language_files.append(os.path.join(dirpath, filename))
    return language_files


def load_treesitter_trees(source_files, log_harnesses=True):
    """Creates treesitter trees for all files in a given list of source files."""
    results = []

    for language in source_files:
        if language == 'cpp':
            for code_file in source_files[language]:
                if not os.path.isfile(code_file):
                    continue
                source_cls = SourceCodeFile(code_file, language)
                if log_harnesses:
                    if source_cls.has_libfuzzer_harness():
                        logger.info('harness: %s', code_file)
                results.append(source_cls)
    return results


def analyse_source_code(source_content: str) -> SourceCodeFile:
    """Returns a source abstraction based on a single source string."""
    source_code = SourceCodeFile(source_file='in-memory string',
                                 language='cpp',
                                 source_content=source_content.encode())
    return source_code
