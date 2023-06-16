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

public class Heuristic8 {
  public static Heuristic8 factory() {
    return new Heuristic8();
  }

  public void testMethod(Long[] array) throws AutoFuzzException {
    this.privateMethod(array);
  }

  public void testMethod(SampleEnum sampleEnum) throws AutoFuzzException {
    this.privateMethod(sampleEnum);
  }

  private void privateMethod(Long[] array) throws AutoFuzzException {
    SampleObject.testStaticMethodLongArray(array);
    (new SampleObject()).testMethodLongArray(array);
  }

  private void privateMethod(SampleEnum sampleEnum) throws AutoFuzzException {
    SampleObject.testStaticMethodEnum(sampleEnum);
    (new SampleObject()).testMethodEnum(sampleEnum);
  }

  class Heuristic8Factory {
    public Heuristic8 genHeuristic8() {
      return new Heuristic8();
    }
  }
}
