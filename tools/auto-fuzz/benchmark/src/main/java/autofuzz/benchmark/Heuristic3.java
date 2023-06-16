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

public class Heuristic3 {
  private Heuristic3() {
    // Deny object creation from constructor
  }

  public static Heuristic3 factory() {
    return new Heuristic3();
  }

  public void testMethod(Boolean[] array) throws AutoFuzzException {
    this.privateMethod(array);
  }

  public void testMethod(Byte b) throws AutoFuzzException {
    this.privateMethod(b);
  }

  public void testMethod(byte[] array) throws AutoFuzzException {
    this.privateMethod(array);
  }

  private void privateMethod(Boolean[] array) throws AutoFuzzException {
    SampleObject.testStaticMethodBooleanArray(array);
    (new SampleObject()).testMethodBooleanArray(array);
  }

  private void privateMethod(Byte b) throws AutoFuzzException {
    SampleObject.testStaticMethodByte(b);
    (new SampleObject()).testMethodByte(b);
  }

  private void privateMethod(byte[] array) throws AutoFuzzException {
    SampleObject.testStaticMethodByteArray(array);
    (new SampleObject()).testMethodByteArray(array);
  }
}
