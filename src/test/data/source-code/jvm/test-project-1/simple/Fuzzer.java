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

package simple;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;

class SimpleClass {
    public SimpleClass() {
        System.out.println("Default Constructor Called");
    }

    public SimpleClass(String param) {
        System.out.println("Constructor with parameter called: " + param.toUpperCase());
    }

    public void simpleMethod() {
        System.out.println("Simple Method Called");
    }

    public void unreachableMethod() {
        System.out.println("Unreachable Method in SimpleClass");
    }
}

public class Fuzzer {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        SimpleClass sc = new SimpleClass(data.consumeString(10));
        sc.simpleMethod();
    }
}
