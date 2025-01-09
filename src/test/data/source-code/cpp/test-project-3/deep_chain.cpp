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

#include "deep_chain.hpp"
#include <iostream>
#include <algorithm>
#include <string>

namespace DeepNamespace {

    void level1(int x) {
        std::cout << "Level 1 called with value: " << x << std::endl;
        if (x > 0) {
            level2(x - 1);
        } else {
            std::cout << "Reached base case in level1" << std::endl;
        }
    }

    void level2(int x) {
        std::cout << "Level 2 called with value: " << x << std::endl;

        // Call to a standard library function
        std::string msg = std::to_string(x);
        std::reverse(msg.begin(), msg.end());
        std::cout << "Reversed value at level2: " << msg << std::endl;

        if (x > 0) {
            level3(x - 1);
        }
    }

    void level3(int x) {
        std::cout << "Level 3 called with value: " << x << std::endl;

        // Call to level 4
        if (x % 2 == 0) {
            level4(x - 1);
        } else {
            std::cout << "Skipping level 4 from level3" << std::endl;
        }
    }

    void level4(int x) {
        std::cout << "Level 4 called with value: " << x << std::endl;

        // Call to a standard library function
        if (x > 0) {
            std::cout << "Substring of 'level4': " << std::string("level4").substr(0, x % 6) << std::endl;
            level5(x - 1);
        } else {
            std::cout << "Reached base case in level4" << std::endl;
        }
    }

    void level5(int x) {
        std::cout << "Level 5 called with value: " << x << std::endl;

        // Base case
        if (x == 0) {
            std::cout << "Reached the deepest level: level5" << std::endl;
        }
    }

    void unreachableFunction(std::string msg) {
        std::cout << "Unreachable Function called with message: " << msg << std::endl;
    }

}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0;
    }

    int input = static_cast<int>(data[0]);
    DeepNamespace::level1(input);

    return 0;
}
