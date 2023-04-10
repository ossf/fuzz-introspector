# OSS-Fuzz scanner utilities

Utilities to easily extract data about OSS-Fuzz projects by querying OSS-Fuzz's
public data.

These utilities will download raw data from oss-fuzz cloud storage
and run the core fuzz introspector analysis on the data. As such, there is a
bit of processing to go through when running these commands. At the same time
they make it easy to test new functionality. Because of this, it's necessary
to set up fuzz-introspector first. You can use the instructions:

```bash
git clone https://github.com/ossf/fuzz-introspector

cd fuzz-introspector
git submodule init
git submodule update

python3 -m virtualenv .venv
. .venv/bin/activate
pip3 install -r ./requirements.txt
cd frontends/python/PyCG
pip3 install .
```

## function_inspector.py

Usage: `python3 ./function_inspector.py {project_name} {function_name}`

Provides summary information about a given function in a given project. This
is centred around reachability and code coverage.

The way you'd do this manually is:

1) Go to our overview page: https://oss-fuzz-introspector.storage.googleapis.com/index.html
2) Find the relevant project
3) search for the function name in the `Project functions overview` table.

Example usage investigating the function: `sshkey_verify` from `openssh` (https://github.com/openssh/openssh-portable/blob/09d8da0849e2791b2500267cda333cd238f38754/sshkey.c#L2120)

```bash
$ python3 ./function_inspector.py openssh sshkey_verify
...
sshkey_verify
  Reached by 6 fuzzers [['/src/openssh/regress/misc/fuzz-harness/privkey_fuzz.cc', '/src/openssh/regress/misc/fuzz-harness/pubkey_fuzz.cc', '/src/openssh/regress/misc/fuzz-harness/sig_fuzz.cc', '/src/openssh/regress/misc/fuzz-harness/sshsig_fuzz.cc', '/src/openssh/regress/misc/fuzz-harness/agent_fuzz.cc', '/src/openssh/regress/misc/fuzz-harness/kex_fuzz.cc']]
  Code coverage: 81.818182
```

We can see the the function is reached by 6 fuzzers and has code coverage of
81.8%.

The above roughly corresponds to navigating to [the relevant section](https://storage.googleapis.com/oss-fuzz-introspector/openssh/inspector-report/20230402/fuzz_report.html#Project-functions-overview) in the
Fuzz Introspector report and searching for `sshkey_verify`:
![screenshot of report](/tools/oss-fuzz-scanner/openssh-verify-key.png)


## function_target_inspector.py
Module for finding functions with no coverage but a lot of complexity.

These often consitute good targets for fuzzers, and, likely missing important
functions for an existing fuzzing set up.

```bash
python3 ./function_target_inspector.py elfutils
Stats as of 2023-04-09
Functions with 0 coverage: 830
Most complex functions with no code coverage:
{
  "function name": "riscv_disasm",
  "code-coverage": 0.0,
  "cyclomatic complexity": 217,
  "accummulated complexity": 239,
  "unreached complexity": 225
}
{
  "function name": "x86_64_disasm",
  "code-coverage": 0.0,
  "cyclomatic complexity": 182,
  "accummulated complexity": 200,
  "unreached complexity": 188
}
{
  "function name": "i386_disasm",
  "code-coverage": 0.0,
  "cyclomatic complexity": 165,
  "accummulated complexity": 183,
  "unreached complexity": 171
}
{
  "function name": "expr_eval",
  "code-coverage": 0.0,
  "cyclomatic complexity": 115,
  "accummulated complexity": 447,
  "unreached complexity": 422
}
{
  "function name": "__libdw_read_begin_end_pair_inc",
  "code-coverage": 0.0,
  "cyclomatic complexity": 67,
  "accummulated complexity": 2449,
  "unreached complexity": 661
```

## branch_blocker_inspector.py

Usage: `python3 branch_blocker_inspector.py {project_name}`

Example:

```bash
python3 branch_blocker_inspector.py htslib

Profile: /src/htslib/test/fuzz/hts_open_fuzzer.c has 659 blokers
{
  "Function where blocker is": "cram_close",
  "Blocker source code location": "/src/htslib/cram/cram_io.c:5532",
  "Complexity blocked": 6556,
  "Num of unique blocked funcs": 1,
  "Unique blocked funcs:": "['cram_write_eof_block']"
}
{
  "Function where blocker is": "cram_close",
  "Blocker source code location": "/src/htslib/cram/cram_io.c:5503",
  "Complexity blocked": 17194,
  "Num of unique blocked funcs": 2,
  "Unique blocked funcs:": "['cram_flush_container_mt', 'cram_update_curr_slice']"
}
{
  "Function where blocker is": "cram_close",
  "Blocker source code location": "/src/htslib/cram/cram_io.c:5514",
  "Complexity blocked": 10769,
  "Num of unique blocked funcs": 4,
  "Unique blocked funcs:": "['cram_flush_result', 'hts_tpool_process_destroy', 'pthread_mutex_destroy', 'hts_tpool_process_flush']"
}
{
  "Function where blocker is": "hts_hopen",
  "Blocker source code location": "/src/htslib/hts.c:1505",
  "Complexity blocked": 2827,
  "Num of unique blocked funcs": 1,
  "Unique blocked funcs:": "['hts_process_opts']"
}
{
  "Function where blocker is": "hts_open_format",
  "Blocker source code location": "/src/htslib/hts.c:900",
  "Complexity blocked": 2733,
  "Num of unique blocked funcs": 5,
  "Unique blocked funcs:": "['strerror', 'hts_log', 'hts_opt_apply', 'hclose_abruptly', '__errno_location']"
}
{
  "Function where blocker is": "bcf_write",
  "Blocker source code location": "/src/htslib/vcf.c:2096",
  "Complexity blocked": 1042,
  "Num of unique blocked funcs": 10,
  "Unique blocked funcs:": "['bcf1_sync', 'bcf_seqname_safe', 'u32_to_le.1828', 'hts_idx_push', 'bgzf_write', 'hts_log', 'u16_to_le.1829', 'bcf_strerror', 'float_to_le.1868', 'i32_to_le.1827']"
}
```
