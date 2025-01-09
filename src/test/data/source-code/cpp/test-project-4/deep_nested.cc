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

#include "deep_nested.hpp"
#include <iostream>

namespace Level1 {
    namespace Level2 {
        namespace Level3 {
            namespace Level4 {

                DeepClass::DeepClass() {
                    std::cout << "DeepClass Constructor" << std::endl;
                    atoi("12");
                }

                DeepClass::~DeepClass() {
                    std::cout << "DeepClass Destructor" << std::endl;
                }

                void DeepClass::deepMethod1(int x) {
                    if (x > 0) {
                        std::cout << "DeepMethod1: Positive " << x << std::endl;
                        deepMethod2("Positive");
                    } else {
                        std::cout << "DeepMethod1: Non-Positive " << x << std::endl;
                        deepMethod2("Non-Positive");
                    }
                }

                void DeepClass::deepMethod2(std::string y) {
                    std::cout << "DeepMethod2: " << y << std::endl;
                    printf("Hello\n");
                }

            }
        }
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0;
    }

    int input = static_cast<int>(data[0]);

    Level1::Level2::Level3::Level4::DeepClass obj;
    obj.deepMethod1(input);

    return 0;
}
