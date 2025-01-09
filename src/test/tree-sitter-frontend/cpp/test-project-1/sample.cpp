/* Copyright 2025 Fuzz Introspector Authors
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

#include "sample.h"
#include <iostream>

namespace OuterNamespace {
    namespace InnerNamespace {
        int nestedFunction(int a, int b) {
            return a + b;
        }
    }

    MyClass::MyClass() {
        std::cout << "Constructor called" << std::endl;
    }

    MyClass::~MyClass() {
        std::cout << "Destructor called" << std::endl;
    }

    void MyClass::memberFunction(int x) {
        if (isPositive(x)) {
            std::cout << "Positive value: " << x << std::endl;
        } else {
            std::cout << "Non-positive value: " << x << std::endl;
        }
    }

    std::string MyClass::getString() const {
        return "Hello, World!";
    }

    void MyClass::staticFunction() {
        std::cout << "Static function called" << std::endl;
    }

    void MyStruct::print() const {
        std::cout << "Field1: " << field1 << ", Field2: " << field2 << std::endl;
    }
}

void globalFunction(int param1, double param2) {
    if (param1 > 0 && param2 > 0.0) {
        std::cout << "Both parameters are positive" << std::endl;
    } else {
        std::cout << "At least one parameter is not positive" << std::endl;
    }
}

bool isPositive(int value) {
    return value > 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0;
    }

    int param = *reinterpret_cast<const int*>(data);

    globalFunction(param, param / 2.0);

    OuterNamespace::MyClass obj;
    obj.memberFunction(param);

    return 0;
}
