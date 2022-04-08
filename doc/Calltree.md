# Calltree

This documentation goes in detail with the calltree.

## Concept
The calltree shows the callsites of a control-flow graph of a given fuzzer. This
is one of the core data structures that Fuzz Introspector use to reason about
fuzzers.

To provide intuition for the calltree consider the following simple code including
a fuzzer:
```c
int unreached_target1(const uint8_t *data) {
    if (data[0] == 0x11) {
        return 1;
    }
    char *mc = (char*)malloc(12);
    if (data[0] == 0x12) {
        return 3;
    }
    return 5;
}

int un(char *n1) {
  return 0;
}

int unreached_target3(const uint8_t *data, size_t *theval) {
    printf("Never reached\n");
    return 5;
}

char *d = { 0x12 };
int target2(const uint8_t *data) {
  if (data[0] == 0x41) return 1;
    unreached_target1(d);
  return 2;
}

int target3(const uint8_t *data) {
  if (data[0] == 0x42) return 4;
  return 3;
}

int fuzz_entry(const uint8_t *data, size_t size) {
  int ret;
  if (size == 2) {
    ret = target2(data);
  }
  else if (size == 3) {
    ret = target3(data);
  }
  else {
    ret = 1;
  }
  return ret;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    fuzz_entry(data, size);
    return 0;
}
```

The calltree of the above code is:

```
LLVMFuzzerTestOneInput
  fuzz_entry
    target2
      unreached_target1
        malloc
    target3
```

Some observations:
- the functions `un` and `unreached_target3` are not reachable by the fuzzer.


## Discrepancies and pitfalls
There are several design decisions in the implementation of the calltree and the
various analyses built on top of it. We list some of these here.

One of the main points to take away from the discrepancies listed here is that calltress
are not perfect and often approximations. This is not something we expect to be solved.

#### Recursion is only displayed once

#### Indirect pointers makes approximate calltrees

#### C++ inheritance makes approximate calltrees

#### Coloring of the calltree does not follow control-flow
