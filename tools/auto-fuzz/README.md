# Auto-fuzz
This tool provides auto-generation capabilities of fuzzers by way of Fuzz
Introspector and OSS-Fuzz.

The idea is largely for now to take as input a Github url to a repository,
and then output a set of OSS-Fuzz projects that include auto-generated fuzzers
for the given project at the Github project.

This is work in progress and things change rapidly. For this reason, there is
little maintenance about the the current state of the generator. However, the
commands below for auto generating fuzzers will remain stable by default.

# Installation and run
To run:
```
cd $WORKDIR

git clone https://github.com/google/oss-fuzz
git clone https://github.com/ossf/fuzz-introspector

cd fuzz-introspector
git submodule init
git submodule update

python3 -m virtualenv .venv
. .venv/bin/activate
pip3 install -r ./requirements.txt
cd frontends/python/PyCG
pip3 install .

# Go into auto-fuzz
cd ../../../tools/auto-fuzz/

# Run a small experiment (it's set to being small by default)
# Currently, only java or python supported for the language option
python3 ./manager.py <language>

# Once it's finished, let's inspect the results.
# Identify the best targets per project
python3 ./post-process.py
```

# Some settings
`constants.py` holds important constants, in particular:
- Constants fo controlling how much effort to put in.
- The github repositories to auto-generate fuzzers for.

When focusing on only testing static analysis and not running, you can disable
runtime checks by setting `should_run_checks` to `False` in `build_and_test_single_possible_target`.
This can be useful for rapidly testing fuzzer generation, as applying the runtime
checks will take tens of minutes when doing checks on 500+ fuzzers per project.

If you want to run larger experiments, simply change the variables in the
`constants.py` file.

# Example fuzzer generated
Setting the `constants.py` to hold the values:

```python
MAX_FUZZERS_PER_PROJECT = 5000
MAX_THREADS = 10

python_git_repos = [
    'https://github.com/executablebooks/markdown-it-py'
]
```

will auto-generate a lot of fuzzers for https://github.com/executablebooks/markdown-it-py.
When running the post process afterwards, we get results:

```
python3 post_process.py
https://github.com/executablebooks/markdown-it-py  ::      autofuzz-0 ::  autofuzz-0-idx-300    ::   766 :: autofuzz-0/autofuzz-0-idx-300/fuzz_1.py
```
which shows the fuzzer at path `autofuzz-0/autofuzz-0-idx-300/fuzz_1.py`
achieves an edge coverage of `766`. The fuzzer generated, as of this writing,
is:
```python
# ... Some licensing for OSS-Fuzz.
import sys
import atheris
# Imports by the generated code
import markdown_it


@atheris.instrument_func
def TestOneInput(data):
  fdp = atheris.FuzzedDataProvider(data)
  val_1 = fdp.ConsumeUnicodeNoSurrogates(24)

  # Class target.
  # Heuristic name: Heuristic 4
  try:
    c1 = markdown_it.main.MarkdownIt()
    c1.render(val_1)
  except(TypeError,):
    pass


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
```

