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

public class Heuristic10 {
  public static Heuristic10 factory() {
    return new Heuristic10();
  }

  public void testMethod(SampleObject object) throws AutoFuzzException {
    this.privateMethod(object);
  }

  public void testMethod(Class<? extends Object> cl) throws AutoFuzzException {
    this.privateMethod(cl);
  }

  private void privateMethod(SampleObject object) throws AutoFuzzException {
    SampleObject.testStaticMethodObject(object);
    object.testMethodObject(new SampleObject());
  }

  private void privateMethod(Class<? extends Object> cl) throws AutoFuzzException {
    SampleObject.testStaticMethodClass(cl);
    (new SampleObject()).testMethodClass(cl);
  }

  class Heuristic10Factory {
    public Heuristic10 genHeuristic10() {
      return new Heuristic10();
    }
  }
}
