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

#include "test.hpp"
#include <iostream>

namespace NamespaceOne {
    void processInput(const std::string& input) {
        std::cout << "NamespaceOne::processInput called with: " << input << std::endl;
    }
}

namespace NamespaceTwo {
    void processInput(const std::string& input) {
        std::cout << "NamespaceTwo::processInput called with: " << input << std::endl;
    }
}

void ClassOne::processInput(const std::string& input) {
    std::cout << "ClassOne::processInput called with: " << input << std::endl;
}

void ClassTwo::processInput(const std::string& input) {
    std::cout << "ClassTwo::processInput called with: " << input << std::endl;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (data == nullptr || size == 0) {
        return 0;
    }
    std::string input(reinterpret_cast<const char*>(data), size);

    NamespaceOne::processInput(input);

    ClassOne obj;
    obj.processInput(input);

    return 0;
}
