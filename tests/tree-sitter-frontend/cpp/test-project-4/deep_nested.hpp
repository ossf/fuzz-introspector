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

#ifndef DEEP_NESTED_HPP
#define DEEP_NESTED_HPP

#include <string>

namespace Level1 {
    namespace Level2 {
        namespace Level3 {
            namespace Level4 {
                class DeepClass {
                public:
                    DeepClass();
                    ~DeepClass();
                    void deepMethod1(int x);
                    void deepMethod2(std::string y);
                };
            }
        }
    }
}

#endif // DEEP_NESTED_HP
