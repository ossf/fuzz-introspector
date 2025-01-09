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

#ifndef SAMPLE_H
#define SAMPLE_H

#include <string>
#include <vector>

namespace OuterNamespace {
    namespace InnerNamespace {
        int nestedFunction(int a, int b);
    }

    class MyClass {
    public:
        MyClass();
        ~MyClass();
        void memberFunction(int x);
        std::string getString() const;
        static void staticFunction();
    };

    struct MyStruct {
        int field1;
        double field2;
        void print() const;
    };
}

void globalFunction(int param1, double param2);
bool isPositive(int value);

#endif // SAMPLE_H
