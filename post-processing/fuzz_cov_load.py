import os
import sys
import fuzz_utils
import logging

l = logging.getLogger(name=__name__)

"""
Module for loading coverage files and parsing them into something we can use in Python.

At the moment only C/C++ is supported. Other languages coming up soon.
"""
class CoverageProfile:
    """
    Class for storing information about a runtime coverage report
    """
    def __init__(self):
        self.functions_hit = set()
        self.covmap = dict()
        self.covreports = list()

    def get_all_hit_functions(self):
        return self.covmap.keys()

    def get_hit_summary(self, funcname):
        """
        returns the hit summary of a give function, in the form of
        a tuple (total_function_lines, hit_lines)
        """
        if funcname not in self.covmap:
            return None, None
        lines_hit = [ht for ln,ht in self.covmap[funcname] if ht > 0]
        return len(self.covmap[funcname]), len(lines_hit)

def llvm_cov_load(target_dir, target_name=None):
    """
    Parses output from commands e.g. 
        llvm-cov show -instr-profile=$profdata_file -object=$target \
          -line-coverage-gt=0 $shared_libraries $LLVM_COV_COMMON_ARGS > ${FUZZER_STATS_DIR}/$target.covreport
    
    This is used to parse C/C++ coverage.

    Some old documentation:

    Reads all of the functions hit across all of the covreport files.
    This is a bit over-approximating in that we dont actually find coverage
    on a per-fuzzer basis, which is what we shuold. 
    The difficulty in finding coverage on a per-fuzzer basis is correlating
    binary files to the introspection done a compile time. Files could be
    moved around and remaned, so we need some mechanism that looks at the 
    internals, e.g. file name and location of LLVMFuzzerTestOneInput. 
    But, we wait a bit with this.
    """
    coverage_reports = fuzz_utils.get_all_files_in_tree_with_regex(target_dir, ".*\.covreport$")
    l.info("Found %d coverage reports"%(len(coverage_reports)))

    cp = CoverageProfile()

    # Check if there is a meaningful profile and if not, we need to use all.
    found_name = False
    if target_name != None:
        for pf in coverage_reports:
            if target_name in pf:
                found_name = True

    for profile_file in coverage_reports:
        # If only coverage from a specific report should be used then filter
        # here. Otherwise, include coverage from everybody.
        if found_name and target_name not in profile_file:
            continue
        l.info("Parsing %s"%(profile_file))
        with open(profile_file, 'rb') as pf:
            cp.covreports.append(profile_file)
            curr_func = None
            for line in pf:
                #print("line:")
                #print(line)
                try:
                    line = line.decode()
                except:
                    try:
                        line = line.decode('unicode-escape')
                    except:
                        continue

                stripped_line = line.replace("\n","")
                if len(stripped_line) > 0 and stripped_line[-1] == ":" and "|" not in stripped_line:
                    #print("We got a function definition: %s"%(line.replace("n","")))
                    if len(line.split(":")) == 3:
                        curr_func = stripped_line.split(":")[1].replace(" ","").replace(":","")
                    else:
                        curr_func = stripped_line.replace(" ","").replace(":","")
                    cp.covmap[curr_func] = list()
                if curr_func != None and "|" in line:
                    #print("Function: %s has line: %s --- %s"%(curr_func, line.replace("\n",""), str(line.split("|"))))
                    try:
                        line_number = int(line.split("|")[0])
                    except:
                        continue
                    try:
                        # write out numbers e.g. 1.2k into 1200
                        hit_times = int(line.split("|")[1].replace("k","00").replace("M","0000").replace(".",""))
                    except:
                        hit_times = 0
                    cp.covmap[curr_func].append((line_number, hit_times))
                    #print("\tLine %d - hit times: %d"%(line_number, hit_times))

                # We should now normalise the potential function name
                if not stripped_line.endswith(":"):
                    continue
                fname = stripped_line
                if ".cpp" in fname:
                    fname = fname.split(".cpp")[-1].replace(":","")
                    fname = fuzz_utils.demangle_cpp_func(fname)
                elif ".c" in fname:
                    fname = fname.split(".c")[-1].replace(":","")
                fname = fname.replace(":", "")
                cp.functions_hit.add(fname)

    return cp

if __name__ == "__main__":
    print("Starting coverage loader")
    cp = llvm_cov_load(".")
    print("Functions hit:")
    for fn in cp.functions_hit:
        print(fn)

    print("Coverage map keys")
    for fn in cp.covmap:
        print(fn)
    print("Coverage loader end")
