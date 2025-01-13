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

#include <stdlib.h>
#include <iostream>


class A1 {
    public:
    A1() {
        printf("Hello\n");
        atoi("12");
    }

    void func1() {
        printf("H\n");
    }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
 
    A1 a;
    a.func1();

    return 0;
}
