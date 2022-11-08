// Copyright 2022 Fuzz Introspector Authors
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
///////////////////////////////////////////////////////////////////////////

package Fuzz;

import com.code_intelligence.jazzer.api.CannedFuzzedDataProvider;
import com.code_intelligence.jazzer.api.FuzzedDataProvider;

public class TestFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    int choice = data.consumeInt(1, 4);
    Human human;

    if (choice == 1) {
      human = new Male();
    } else if (choice == 2) {
      human = new Female();
    } else if (choice == 3) {
      human = new Robot();
    } else {
      human = new Android();
    }

    human.getName();
  }

  public static void main(String[] args) {
    TestFuzzer.fuzzerTestOneInput(new CannedFuzzedDataProvider("RANDOM"));
  }
}
