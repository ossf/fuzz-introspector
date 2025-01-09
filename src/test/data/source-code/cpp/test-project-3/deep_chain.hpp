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

#ifndef DEEP_CHAIN_HPP
#define DEEP_CHAIN_HPP

#include <string>

namespace DeepNamespace {
    void level1(int x);
    void level2(int x);
    void level3(int x);
    void level4(int x);
    void level5(int x);

    void unreachableFunction(std::string msg);
}

#endif // DEEP_CHAIN_HPP
