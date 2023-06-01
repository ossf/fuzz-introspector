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

import ast
import os
import sys
import shutil
import importlib.util


class FuzzerVisitor(ast.NodeVisitor):
    def __init__(self, ast_content):
        print("Hello")
        self.ast_content = ast_content
        self.current_scope = []

        self.fuzzer_entrypoint = None
        self.fuzzer_imports = []
        self.fuzzer_packages = []

    def visit_Module(self, node):
        print("Visiting module")
        print(node)
        self.generic_visit(node)

    def visit_With(self, node):
        print("In with")
        print(node.body)
        for elem in node.body:
            print("Iterating %s" % (elem))
            self.visit(elem)

    def visit_Import(self, node):
        print("Import")
        for alias in node.names:
            print("- %s" % (alias.name))
            self.fuzzer_imports.append(alias.name)

    def visit_ImportFrom(self, node):
        print("From import")
        mod = node.module
        for _import in node.names:
            imported_module = mod + "." + _import.name
            if imported_module.endswith(".*"):
                imported_module = imported_module[:-2]
            self.fuzzer_imports.append(imported_module)

    def visit_Call(self, node):
        if len(self.current_scope) == 0:
            scope = "global"
        else:
            scope = self.current_scope[-1]
        print("call instruction: %s" % (ast.dump(node)))
        print("Inside of call instruction -- %s" % (scope))
        if isinstance(node.func, ast.Name):
            print("- [N] %s" % (node.func.id))
        if isinstance(node.func, ast.Attribute):
            print("%s" % (node.func))
            lhs = ""
            lhs_obj = node.func
            while isinstance(lhs_obj, ast.Attribute):
                tmp = lhs_obj.value
                lhs = "." + lhs_obj.attr + lhs
                lhs_obj = tmp
                if isinstance(tmp, ast.Name):
                    break
                if isinstance(lhs_obj, ast.Call):
                    self.visit_Call(lhs_obj)
                    lhs_obj = None
            if lhs_obj is not None:
                try:
                    lhs = lhs_obj.id + lhs
                except AttributeError:
                    lhs = ""
            print(" [C] %s" % (lhs))

            # Check if we have atheris.Setup
            if lhs == "atheris.Setup":
                print("We have the set up function")
                # Identify the second argument to the function
                # Target function is the second argument
                arg = node.args[1]
                if isinstance(arg, ast.Name):
                    self.fuzzer_entrypoint = arg.id

                for arg in node.args:
                    print("- arg: %s" % (arg))

    def visit_FunctionDef(self, node):
        print("Function definition: %s" % (node.name))
        self.current_scope.append(node.name)
        self.generic_visit(node)
        self.current_scope = self.current_scope[:-1]

    def analyze(self):
        self.visit(self.ast_content)

    def print_specifics(self):
        print("#" * 50)
        print("Fuzzer specification")
        if self.fuzzer_entrypoint is None:
            ep = "Found none"
        else:
            ep = self.fuzzer_entrypoint
        print("- Fuzzer entrypoint: %s" % (ep))
        print("- Fuzzer imports:")
        for _import in self.fuzzer_imports:
            print("  - %s" % (_import))
            if _import.count(".") > 0:
                _import = _import.split(".")[0]
                print("Refining import to %s" % (_import))

            # Let's try and see if these are searchable
            try:
                specs = importlib.util.find_spec(_import)
            except ModuleNotFoundError:
                continue
            except ImportError:
                continue
            print("No error")
            if specs is not None:
                print("Spec:")
                print(specs)
                avoid = ['atheris', 'sys', 'os']
                if _import not in avoid:
                    if specs.submodule_search_locations:
                        for elem in specs.submodule_search_locations:
                            print("Checking --- %s" % (elem))
                            if (
                                ("/usr/local/lib/" in elem or "/usr/lib/" in elem)
                                and "site-packages" not in elem
                            ):
                                # skip packages that are builtin packacges
                                # Check if we can refine
                                if elem.count(".") > 1:
                                    print("Has such a count")
                                continue
                            print("Adding --- %s" % (elem))
                            self.fuzzer_packages.append(elem)
            else:
                print("Spec is none")
        print("Iterating")
        for pkg in self.fuzzer_packages:
            print("package: %s" % (pkg))


def get_package_paths(filename):
    with open(filename, "r") as f:
        content = f.read()

    print("Fuzzer visitor")
    fuzz_visitor = FuzzerVisitor(ast.parse(content))
    fuzz_visitor.analyze()
    fuzz_visitor.print_specifics()

    return fuzz_visitor.fuzzer_packages


if __name__ == "__main__":
    filename = sys.argv[1]
    if len(sys.argv) > 2:
        is_oss_fuzz = True
    else:
        is_oss_fuzz = False
    fuzz_packages = get_package_paths(filename)
    print("After main")
    for fpkg in fuzz_packages:
        print("- %s" % (fpkg))
    with open("tmp-packages.txt", "w") as pkgf:
        for fpkg in fuzz_packages:
            print("- %s" % (fpkg))
            pkgf.write(fpkg)
            pkgf.write("\n")

    if is_oss_fuzz:
        if not os.path.isdir("/src/pyintro-pack-deps"):
            os.mkdir("/src/pyintro-pack-deps")
        for pkg in fuzz_packages:
            dst_dir = "/src/pyintro-pack-deps/%s" % (os.path.basename(pkg))
            if os.path.isdir(pkg) and not os.path.isdir(dst_dir):
                shutil.copytree(pkg, dst_dir)
