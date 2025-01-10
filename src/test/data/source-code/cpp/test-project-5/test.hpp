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

#ifndef TEST_HPP
#define TEST_HPP

#include <string>

namespace NamespaceOne {
    void processInput(const std::string& input);
}

namespace NamespaceTwo {
    void processInput(const std::string& input);
}

class ClassOne {
public:
    void processInput(const std::string& input);
};

class ClassTwo {
public:
    void processInput(const std::string& input);
};

#endif // TEST_HPP
