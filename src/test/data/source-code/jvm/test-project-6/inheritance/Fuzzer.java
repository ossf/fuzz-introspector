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

package inheritance;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;

class SuperClass {
    void superMethod() {
        System.out.println("SuperClass Method Called");
        recursiveHelper(2);
    }

    void recursiveHelper(int n) {
        if (n > 0) {
            System.out.println("Superclass Recursion: " + n);
            recursiveHelper(n - 1);
        }
    }

    void unreachableSuperMethod() {
        System.out.println("Unreachable Method in SuperClass");
    }
}

class SubClass extends SuperClass {
    @Override
    void superMethod() {
        System.out.println("SubClass Method Overriding SuperClass");
        super.superMethod();
    }

    void unreachableSubMethod() {
        System.out.println("Unreachable Method in SubClass");
    }
}

public class Fuzzer {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        SuperClass obj;
        if ("subclass".equals(data.consumeString(10))) {
            obj = new SubClass();
        } else {
            obj = new SuperClass();
        }
        obj.superMethod();
    }
}
