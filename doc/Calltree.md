# Calltree

This documentation goes in detail with the calltree.

- [Calltree](#calltree)
  * [Concept](#concept)
  * [Discrepancies and pitfalls](#discrepancies-and-pitfalls)
      - [Recursion is only displayed once](#recursion-is-only-displayed-once)
      - [Indirect pointers makes approximate calltrees](#indirect-pointers-makes-approximate-calltrees)
      - [C++ inheritance makes approximate calltrees](#c---inheritance-makes-approximate-calltrees)
        * [Example 1](#example-1)
        * [Example 2](#example-2)
        * [Example 3](#example-3)
        * [Example 4](#example-4)
      - [Coloring of the calltree does not follow control-flow](#coloring-of-the-calltree-does-not-follow-control-flow)

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

Fuzz Introspector does not do much work to resolve indirect calls at the moment. As such,
indirect calls will likely not be shown in the calltree.

One exception is C++ VTables, where Fuzz Introspector makes an effort into resolving calls.
In particular, Fuzz Introspector will do *some* analysis on the LLVM IR to extract the class
and function of a given indirect call that is a VTable call. See below examples for more
about how Fuzz Introspector resolves calltrees of C++ code.

#### C++ inheritance makes approximate calltrees
Extracting calltrees from C++ code is non-trivial. To show this, consider the following C++
classes:
```c++
class B
{
public:
  virtual void bar();
  virtual void qux();
};

void B::bar()
{
  std::cout << "This is B's implementation of bar" << std::endl;
}

void B::qux()
{
  std::cout << "This is B's implementation of qux" << std::endl;
}


class C : public B
{
public:
  void bar() override;
};

void C::bar()
{
  std::cout << "This is C's implementation of bar" << std::endl;
}
```

Then, consider the fuzzers and their respective calltrees as extracted by Fuzz Introspector:

##### Example 1
```c++
void ex1() {
  B* b = new B();
  b->bar();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  ex1();
  return 0;
}
```
The corresponding calltree as extract by Fuzz Introspector:

##### Example 2
```c++
void ex2() {
  C* c = new C();
  c->bar();
}
```
The corresponding calltree as extract by Fuzz Introspector:

##### Example 3
```c++
void ex3() {
  B* b = new C();
  b->bar();
}
```
The corresponding calltree as extract by Fuzz Introspector:

##### Example 4
```c++
void ex4(size_t s) {
  B *t;

  if (s < 10) {
    t = new B();
  }
  else {
    t = new C();
  }
  t->bar();
}
```
The corresponding calltree as extract by Fuzz Introspector:


#### Coloring of the calltree does not follow control-flow
Runtime coverage is not correlated with control-flow: a function may be executed once
during runtime extraction, but this does not mean all places that reference the function
are executed. We make no efforts to analyse if coverage makes sense from a control-flow
perspective as it brings other issues (see below).

For example, consider this fuzzer:

```c
void C() {
  printf("Hello");
}

void D() {
  printf("D");
  C();  
} 

void A(size_t arg1, size_t arg2) {
  if (arg1 != arg2) {
    D();
  }
}

void B(size_t arg1, size_t arg2) {
  if (arg1 != arg2) {
    C();
  }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  A(size, size);
  B(size, 3);
}
```

In this case `D` will never be reached, but `C` will be reached. Thus, when we visualise the
calltree of the application `C` will be green but `D` will be red, despite `C` being a child
of `D` (`B` too calls into C, which is what makes it green).

Fuzz-introspector used to have a heuristic that would analyse the control-flow and for each
red node in the calltree would make the children of that node red as well. We decided to remove
this as it brought some other issues, e.g. when looking at the coverage report and correlating
with the calltree sometimes you would end up looking at code that was covered in the coverage
report but the calltree would say it was red. As such, we switched it back to being fully verbose
in the sense that the calltree shows control-flow and we simply overlay it with the runtime
coverage data without doing any analysis on it.

