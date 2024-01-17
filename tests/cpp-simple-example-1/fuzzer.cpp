/* Copyright 2021 Fuzz Introspector Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <iostream>

class B
{
public:
  int value1;
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

void ex1() {
  B* b = new B();
  b->bar();
}

void ex2() {
  C* c = new C();
  c->bar();
}

void ex3() {
  B* b = new C();
  b->bar();
}

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

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  ex1();
  ex2();
  ex3();
  ex4(size);
  return 0;
}
