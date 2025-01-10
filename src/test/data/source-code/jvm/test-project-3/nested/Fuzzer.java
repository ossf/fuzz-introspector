// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////
package nested;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;

class NestedClass {
    static class InnerClass {
        void innerMethod() {
            System.out.println("Inner Method Called");
        }

        void unreachableInnerMethod() {
            System.out.println("Unreachable Method in InnerClass");
        }
    }
}

class RecursiveClass {
    void recursiveMethod(int n) {
        if (n > 0) {
            System.out.println("Recursion depth: " + n);
            recursiveMethod(n - 1);
        }
    }

    void unreachableRecursiveHelper() {
        System.out.println("Unreachable Recursive Helper Method");
    }
}

public class Fuzzer {
    @FuzzTest
    public static void test(FuzzedDataProvider data) {
        NestedClass.InnerClass ic = new NestedClass.InnerClass();
        ic.innerMethod();

        RecursiveClass rc = new RecursiveClass();
        rc.recursiveMethod(3);
    }
}
