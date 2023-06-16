// Copyright 2023 Fuzz Introspector Authors
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

package autofuzz.benchmark;

import autofuzz.benchmark.object.*;

public class Heuristic6 {
  private SampleObject object;

  public Heuristic6() {
    object = null;
  }

  public void settings(SampleObject object) {
    this.object = object;
  }

  public static Heuristic6 factory() {
    return new Heuristic6();
  }

  public void testMethod(short[] array) throws AutoFuzzException {
    this.privateMethod(array);
  }

  public void testMethod(Short[] array) throws AutoFuzzException {
    this.privateMethod(array);
  }

  private void privateMethod(short[] array) throws AutoFuzzException {
    SampleObject.testStaticMethodShortArray(array);
    if (this.object != null) {
      this.object.testMethodShortArray(array);
    }
  }

  private void privateMethod(Short[] array) throws AutoFuzzException {
    SampleObject.testStaticMethodShortArray(array);
    if (this.object != null) {
      this.object.testMethodShortArray(array);
    }
  }

  class Heuristic6Factory {
    public Heuristic6 genHeuristic6() {
      return new Heuristic6();
    }
  }
}
