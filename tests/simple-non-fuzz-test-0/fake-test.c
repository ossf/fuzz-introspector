/* Copyright 2024 Fuzz Introspector Authors
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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include <strings.h>


int obvious_fuzzer_entrypoint(const char *data, size_t size) {
    // Parse complex data etc.
    if (size == 5) {
        return 2;
    }
    if (size < 2) {
        return 0;
    }
    return strlen(data);
}

void test1() {
    obvious_fuzzer_entrypoint("lorem ipsum dolor sit amet", 123);
}

void test2() {
    obvious_fuzzer_entrypoint("lorem amet", 12);
}

int main() {
    test1();
    test2();
}
