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

public class Heuristic4 {
  private Heuristic4() {
    // Deny object creation from constructor
  }

  public void testMethod(Byte[] array) throws AutoFuzzException {
    this.privateMethod(array);
  }

  public void testMethod(Short sh) throws AutoFuzzException {
    this.privateMethod(sh);
  }

  private void privateMethod(Byte[] array) throws AutoFuzzException {
    SampleObject.testStaticMethodByteArray(array);
    (new SampleObject()).testMethodByteArray(array);
  }

  private void privateMethod(Short sh) throws AutoFuzzException {
    SampleObject.testStaticMethodShort(sh);
    (new SampleObject()).testMethodShort(sh);
  }

  class Heuristic4Factory {
    public Heuristic4 genHeuristic4() {
      return new Heuristic4();
    }
  }
}
