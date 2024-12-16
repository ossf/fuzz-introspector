# Fuzz Introspector Python Package

Library for analysing fuzzer-relevant components of source code.

Example:

```python
from fuzz_introspector.frontends import core

SAMPLE="""void parse(const char *data, size_t size) {
  return;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  parse((const char*)data, size)
}
"""

source = core.analyse_source_file(SAMPLE, 'c')
func = source.get_function_node('LLVMFuzzerTestOneInput')
if func:
    print(func.callsites())
```

Running the above:

```sh
$ python3 example.py
[('parse', (122, 127))]
```
