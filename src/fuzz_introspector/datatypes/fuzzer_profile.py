# Copyright 2022 Fuzz Introspector Authors
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
"""Fuzzer profile"""

import os
import logging

from typing import (
    Any,
    Dict,
    List,
    Optional,
    Set,
    Tuple,
)

from fuzz_introspector import (cfg_load, code_coverage, json_report, utils)
from fuzz_introspector.datatypes import function_profile
from fuzz_introspector.exceptions import DataLoaderError

logger = logging.getLogger(name=__name__)


class FuzzerProfile:
    """
    Class for storing information about a given Fuzzer.
    This class essentially holds data corresponding to the output of run of the LLVM
    plugin. That means, the output from the plugin for a single fuzzer.
    """

    def __init__(self,
                 cfg_file: str,
                 frontend_yaml: Dict[Any, Any],
                 target_lang: str = "c-cpp") -> None:
        # Defaults
        self.binary_executable: str = ""
        self.file_targets: Dict[str, Set[str]] = dict()
        self.coverage: Optional[code_coverage.CoverageProfile] = None
        self.all_class_functions: Dict[
            str, function_profile.FunctionProfile] = dict()
        self.all_class_constructors: Dict[
            str, function_profile.FunctionProfile] = dict()
        self.branch_blockers: List[Any] = []

        self._target_lang = target_lang
        self.introspector_data_file = cfg_file

        # Load calltree file
        self.fuzzer_callsite_calltree = cfg_load.data_file_read_calltree(
            cfg_file)

        # Read yaml data (as dictionary) from frontend
        try:
            self.fuzzer_source_file: str = frontend_yaml['Fuzzer filename']
        except KeyError:
            raise DataLoaderError("Fuzzer filename not in loaded yaml")

        # Read entrypoint of fuzzer if this is a Python module
        if target_lang == "python":
            self.entrypoint_fun = frontend_yaml['ep']['func_name']
            self.entrypoint_mod = frontend_yaml['ep']['module']

        # Read entrypoint of fuzzer if this is a jvm module
        if target_lang == "jvm":
            self.entrypoint_method = frontend_yaml['Fuzzing method']

        self._set_function_list(frontend_yaml)
        self.dst_to_fd_cache: Dict[str,
                                   function_profile.FunctionProfile] = dict()

    @property
    def target_lang(self):
        """Language the fuzzer is written in"""
        return self._target_lang

    @property
    def entrypoint_function(self):
        """The name of the fuzzer entrypoint"""

        # if set in the evironment use that
        ep_env = os.environ.get('FI_ENTRYPOINT', None)
        if ep_env:
            return ep_env
        if self.target_lang == "c-cpp":
            return "LLVMFuzzerTestOneInput"
        elif self.target_lang == "python":
            return self.entrypoint_fun
        elif self.target_lang == "jvm":
            cname = self.fuzzer_source_file
            mname = self.entrypoint_method
            return f"[{cname}].{mname}"
        else:
            return None

    @property
    def identifier(self):
        """Fuzzer identifier"""
        if self._target_lang == "c-cpp":
            if self.binary_executable != "":
                return os.path.basename(self.binary_executable)

        elif self._target_lang == "python":
            return os.path.basename(self.fuzzer_source_file).replace(".py", "")

        elif self._target_lang == "jvm":
            # Class name is used for jvm identifier
            return os.path.basename(self.fuzzer_source_file)

        return self.fuzzer_source_file

    @property
    def max_func_call_depth(self):
        """The maximum depth of all callsites in the fuzzer's calltree."""
        max_depth = 0
        for callsite in cfg_load.extract_all_callsites(
                self.fuzzer_callsite_calltree):
            if callsite.depth > max_depth:
                max_depth = callsite.depth
        return max_depth

    def has_entry_point(self) -> bool:
        """Returns whether an entrypoint is identified"""
        if self.target_lang == "c-cpp":
            return self.entrypoint_function in self.all_class_functions

        elif self.target_lang == "python":
            return self.entrypoint_function is not None

        elif self.target_lang == "jvm":
            for name in self.all_class_functions:
                if name.startswith(self.entrypoint_function):
                    return True

        return False

    def func_is_entrypoint(self, demangled_func_name: str) -> bool:
        if self.target_lang == "jvm":
            return demangled_func_name.startswith(self.entrypoint_function)
        if (demangled_func_name != self.entrypoint_function
                and self.entrypoint_function not in demangled_func_name):
            return False
        return True

    def resolve_coverage_link(self, cov_url: str, source_file: str,
                              lineno: int, function_name: str) -> str:
        """Resolves a link to a coverage report."""
        return utils.resolve_coverage_link(cov_url, source_file, lineno,
                                           function_name, self.target_lang)

    def refine_paths(self, basefolder: str) -> None:
        """Iterate over source files in the calltree and file_targets and remove
        the fuzzer's basefolder from the path.

        The main point for doing this is clearing any prefixed path that may
        exist. This is, for example, the case in OSS-Fuzz projects where most
        files will be prefixed with /src/project_name.
        """
        # Only do this if basefolder is not wrong
        if basefolder == "/":
            return

        # TODO (David): this is an over-approximation? We should not replace all throughout,
        # but only the start of the string.
        self.fuzzer_source_file = self.fuzzer_source_file.replace(
            basefolder, "")

        if self.fuzzer_callsite_calltree is not None:
            all_callsites = cfg_load.extract_all_callsites(
                self.fuzzer_callsite_calltree)
            for cs in all_callsites:
                cs.dst_function_source_file = cs.dst_function_source_file.replace(
                    basefolder, "")

            new_dict = {}
            for key in self.file_targets:
                new_dict[key.replace(basefolder, "")] = self.file_targets[key]
            self.file_targets = new_dict

    def get_callsites(self):
        return cfg_load.extract_all_callsites(self.fuzzer_callsite_calltree)

    def reaches_file(self,
                     file_name: str,
                     basefolder: Optional[str] = None) -> bool:
        """Identifies if the fuzzer statically reaches a given file

        :param file_name: file to check if fuzzer reaches
        :type file_name: str

        :param basefolder: basefolder path. If not `None` will removed from
                           `file_name` argument.
        :type basefolder: str

        :returns: `True` if the fuzzer statically reaches the file. `False`
                  otherwise.
        :rtype: bool
        """
        if file_name in self.file_targets:
            return True

        # Only some file paths have removed base folder. We must check for
        # both if basefolder is set.
        if basefolder is not None:
            return file_name.replace(basefolder, "") in self.file_targets
        return False

    def reaches_func(self, func_name: str) -> bool:
        """Identifies if the fuzzer statically reaches a given function

        :param func_name: function to check for
        :type func_name: str

        :rtype: bool
        :returns: `True` if the fuzzer statically reaches the function. `False`
                  otherwise.
        """
        return func_name in self.functions_reached_by_fuzzer

    def correlate_executable_name(self, correlation_dict) -> None:
        for elem in correlation_dict['pairings']:
            if os.path.basename(self.introspector_data_file
                                ) in f"{elem['fuzzer_log_file']}.data":
                self.binary_executable = str(elem['executable_path'])

                lval = os.path.basename(self.introspector_data_file)
                rval = f"{elem['fuzzer_log_file']}.data"
                logger.info(f"Correlated {lval} with {rval}")

    def get_key(self) -> str:
        """Returns the "key" we use to identify this Fuzzer profile."""
        if self.binary_executable != "":
            return os.path.basename(self.binary_executable)

        return self.fuzzer_source_file

    def _propagate_functions_reached(self) -> None:
        """Accummulates all functions reached by a given fuzzer. This is
        achieved by iterating the outgoing edges of each function recursively
        """
        new_all_class_functions: Dict[
            str, function_profile.FunctionProfile] = dict()

        for func in self.all_class_functions:
            worklist = []
            max_depth = 0
            for func_reached in self.all_class_functions[
                    func].functions_reached:
                worklist.append((func_reached, 1))
            visited = set()

            while len(worklist) > 0:
                elem, depth = worklist.pop()
                if depth > max_depth:
                    max_depth = depth

                if elem in visited:
                    continue
                visited.add(elem)

                # Check if we have done this function already.
                try:
                    fd = new_all_class_functions[elem]
                    visited.update(set(fd.functions_reached))
                    tmp_depth = fd.function_depth + depth
                    max_depth = max(max_depth, tmp_depth)
                    continue
                except KeyError:
                    pass

                # Otherwise traverse the functions reached.
                try:
                    for func_reached2 in self.all_class_functions[
                            elem].functions_reached:
                        worklist.append((func_reached2, depth + 1))
                except KeyError:
                    pass

            # Save the work
            new_all_class_functions[func] = self.all_class_functions[func]
            new_all_class_functions[func].functions_reached = list(visited)
            new_all_class_functions[func].function_depth = max_depth
        self.all_class_functions = new_all_class_functions

    def _set_fd_cache(self):
        for fd_k, fd in self.all_class_functions.items():
            self.dst_to_fd_cache[utils.demangle_jvm_func(
                fd.function_source_file, fd.function_name)] = fd
            self.dst_to_fd_cache[utils.normalise_str(fd.function_name)] = fd

    def accummulate_profile(self, target_folder: str, return_dict: None,
                            uniq_id: None, semaphore: None) -> None:
        """Triggers various analyses on the data of the fuzzer. This is used
        after a profile has been initialised to generate more interesting data.
        """
        if semaphore is not None:
            semaphore.acquire()

        logger.info("%s: propagating functions reached" % (self.identifier))
        self._propagate_functions_reached()
        logger.info("%s: setting reached funcs" % (self.identifier))
        self._set_all_reached_functions()
        logger.info("%s: setting unreached funcs" % (self.identifier))
        self._set_all_unreached_functions()
        logger.info("%s: loading coverage" % (self.identifier))
        self._load_coverage(target_folder)
        logger.info("%s: setting file targets" % (self.identifier))
        self._set_file_targets()
        logger.info("%s: setting total basic blocks" % (self.identifier))
        self._set_total_basic_blocks()
        logger.info("%s: setting cyclomatic complexity" % (self.identifier))
        self._set_total_cyclomatic_complexity()
        logger.info("%s: setting fd cache" % (self.identifier))
        self._set_fd_cache()
        logger.info("%s: finished accummulating profile" % (self.identifier))
        if return_dict is not None:
            return_dict[uniq_id] = self
        if semaphore is not None:
            semaphore.release()

    def get_cov_uncovered_reachable_funcs(self) -> List[str]:
        """Gets all functions that are statically reachable but are not
        covered by runtime coverage.

        Returns:
            List with names of all the functions that are reachable but not
            covered.
            If there is no coverage information returns empty list.
        """
        if self.coverage is None:
            return []

        uncovered_funcs = []
        for funcname in self.functions_reached_by_fuzzer:
            total_func_lines, hit_lines, hit_percentage = self.get_cov_metrics(
                funcname)
            if total_func_lines is None:
                uncovered_funcs.append(funcname)
                continue
            if hit_lines == 0:
                uncovered_funcs.append(funcname)
        return uncovered_funcs

    def is_file_covered(self,
                        file_name: str,
                        basefolder: Optional[str] = None) -> bool:
        """Identifies whether a file is covered by runtime code coverage

        :param file_name: file name
        :type file_name: str

        :param basefolder: basefolder to apply on the file name
        :type basefolder: str

        :rtype: bool
        :returns: `True` if the file is covered by runtime code coverage,
                  `False` otherwise.
        """
        # We need to refine the pathname to match how coverage file paths are.
        file_name = os.path.abspath(file_name)

        # Refine filename if needed
        if basefolder is not None and basefolder != "/":
            new_file_name = file_name.replace(basefolder, "")
        else:
            new_file_name = file_name

        for funcname in self.all_class_functions:
            # Check it's a relevant filename
            func_file_name = self.all_class_functions[
                funcname].function_source_file
            if basefolder is not None and basefolder != "/":
                new_func_file_name = func_file_name.replace(basefolder, "")
            else:
                new_func_file_name = func_file_name
            if func_file_name != file_name and new_func_file_name != new_file_name:
                continue
            # Return true if the function is hit
            tf, hl, hp = self.get_cov_metrics(funcname)
            if hp is not None and hp > 0.0:
                if func_file_name in self.file_targets or new_file_name in self.file_targets:
                    return True
        return False

    def get_cov_metrics(
            self, funcname: str
    ) -> Tuple[Optional[int], Optional[int], Optional[float]]:
        """Fethes data points on runtime code coverage for a given function.

        A triplet is returned where the first element is the total number of lines
        in the function, the second element is a list of whether each line was
        covered at runtime or not, and the third element is the percentage of lines
        covered by runtime covevrage.

        :param funcname: function to check for.
        :type funcname: str

        :rtype: Tuple[Optional[int], Optional[int], Optional[float]]
        :returns: Triplet of int, int, float indicated numbers described above. Or,
                  a triplet of `None` in the event an error ocurred.
        """
        if self.coverage is None:
            return None, None, None
        try:
            total_func_lines, hit_lines = self.coverage.get_hit_summary(
                funcname)
            if total_func_lines is None or hit_lines is None:
                return None, None, None
            if total_func_lines == 0:
                return 0, 0, 0
            else:
                hit_percentage = (hit_lines / total_func_lines) * 100.0
                return total_func_lines, hit_lines, hit_percentage
        except Exception:
            return None, None, None

    def write_stats_to_summary_file(self) -> None:
        file_target_count = len(
            self.file_targets) if self.file_targets is not None else 0
        json_report.add_fuzzer_key_value_to_report(
            self.identifier, "stats", {
                "total-basic-blocks": self.total_basic_blocks,
                "total-cyclomatic-complexity":
                self.total_cyclomatic_complexity,
                "file-target-count": file_target_count,
            })

    def _set_all_reached_functions(self) -> None:
        """Sets self.functions_reached_by_fuzzer to all functions reached by
        the fuzzer. This is based on identifying all functions reached by the
        fuzzer entrypoint function, e.g. LLVMFuzzerTestOneInput in C/C++.
        """
        # Find C/CPP entry point
        if self._target_lang == "c-cpp":
            if self.entrypoint_function in self.all_class_functions:
                self.functions_reached_by_fuzzer = (self.all_class_functions[
                    self.entrypoint_function].functions_reached)
                self.functions_reached_by_fuzzer.append(
                    self.entrypoint_function)
                return

        # Find Python entrypoint
        elif self._target_lang == "python":
            ep_key = f"{self.entrypoint_mod}.{self.entrypoint_fun}"
            reached = self.all_class_functions[ep_key].functions_reached
            self.functions_reached_by_fuzzer = reached
            self.functions_reached_by_fuzzer.append(self.entrypoint_function)
            return

        # Find JVM entrypoint
        elif self._target_lang == "jvm":
            entrypoint = None
            for name in self.all_class_functions:
                if name.startswith(self.entrypoint_function):
                    entrypoint = name
                    break
            if entrypoint:
                self.functions_reached_by_fuzzer = (
                    self.all_class_functions[entrypoint].functions_reached)
                self.functions_reached_by_fuzzer.append(entrypoint)
                return

        raise DataLoaderError("Can not identify entrypoint")

    def _set_all_unreached_functions(self) -> None:
        """Sets self.functions_unreached_by_fuzzer to all functions that are
        statically unreached. This is computed as the set difference between
        self.all_class_functions and self.functions_reached_by_fuzzer.
        """
        self.functions_unreached_by_fuzzer = [
            f.function_name for f in self.all_class_functions.values()
            if f.function_name not in self.functions_reached_by_fuzzer
        ]

    def _load_coverage(self, target_folder: str) -> None:
        """Load coverage data for this profile"""
        logger.info(f"Loading coverage of type {self.target_lang}")
        if self.target_lang == "c-cpp":
            if os.getenv('FI_KERNEL_COV', ''):
                self.coverage = code_coverage.load_kernel_cov(
                    os.getenv('FI_KERNEL_COV'))
            else:
                self.coverage = code_coverage.load_llvm_coverage(
                    target_folder, self.identifier)
        elif self.target_lang == "python":
            self.coverage = code_coverage.load_python_json_coverage(
                target_folder)
            if self.coverage is not None:
                self.coverage.correlate_python_functions_with_coverage(
                    self.all_class_functions)
        elif self.target_lang == "jvm":
            self.coverage = code_coverage.load_jvm_coverage(
                target_folder, self.identifier)
        else:
            raise DataLoaderError(
                "The profile target has no coverage loading support")

    def _get_target_fuzzer_filename(self) -> str:
        return (os.path.basename(self.fuzzer_source_file).replace(
            ".cpp", "").replace(".cc", "").replace(".c", ""))

    def _set_file_targets(self) -> None:
        """Sets self.file_targets to be a dictionarty of string to string.
        Each key in the dictionary is a filename and the corresponding value is
        a set of strings containing strings which are the names of the functions
        in the given file that are reached by the fuzzer.
        """
        if self.fuzzer_callsite_calltree is not None:
            all_callsites = cfg_load.extract_all_callsites(
                self.fuzzer_callsite_calltree)
            for cs in all_callsites:
                if cs.dst_function_source_file.replace(" ", "") == "":
                    continue
                if cs.dst_function_source_file not in self.file_targets:
                    self.file_targets[cs.dst_function_source_file] = set()
                self.file_targets[cs.dst_function_source_file].add(
                    cs.dst_function_name)

    def _set_total_basic_blocks(self) -> None:
        """Sets self.total_basic_blocks to the sum of basic blocks of all the
        functions reached by this fuzzer.
        """
        total_basic_blocks = 0
        for func in self.functions_reached_by_fuzzer:
            try:
                fd = self.all_class_functions[func]
                total_basic_blocks += fd.bb_count
            except Exception as e:
                logger.debug(e)
                pass
        self.total_basic_blocks = total_basic_blocks

    def _set_total_cyclomatic_complexity(self) -> None:
        """Sets self.total_cyclomatic_complexity to the sum of cyclomatic
        complexity of all functions reached by this fuzzer.
        """
        self.total_cyclomatic_complexity = 0
        for func in self.functions_reached_by_fuzzer:
            try:
                fd = self.all_class_functions[func]
                self.total_cyclomatic_complexity += fd.cyclomatic_complexity
            except Exception as e:
                logger.debug(e)
                pass

    def _set_function_list(self, frontend_yaml: Dict[Any, Any]) -> None:
        """Read all function field from yaml data dictionary into
        instances of FunctionProfile
        """
        for elem in frontend_yaml['All functions']['Elements']:
            if self._is_func_name_missing_normalisation(elem['functionName']):
                logger.info(
                    f"May have non-normalised function: {elem['functionName']}"
                )

            func_profile = function_profile.FunctionProfile(elem)
            logger.debug(f"Adding {func_profile.function_name}")

            if self.target_lang == "jvm" and "<init>" in elem['functionName']:
                # Store JVM constructor separately
                self.all_class_constructors[
                    func_profile.function_name] = func_profile
            else:
                # Store the functions
                self.all_class_functions[
                    func_profile.function_name] = func_profile

    def _is_func_name_missing_normalisation(self, func_name: str) -> bool:
        if "." in func_name:
            split_name = func_name.split(".")
            if split_name[-1].isnumeric():
                return True
        return False
