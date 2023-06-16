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

public class Heuristic2sp {
  public void testMethod(int[] array) throws AutoFuzzException {
    this.privateMethod(array);
  }

  public void testMethod(boolean bool) throws AutoFuzzException {
    this.privateMethod(bool);
  }

  public void testMethod(boolean[] array) throws AutoFuzzException {
    this.privateMethod(array);
  }

  private void privateMethod(int[] array) throws AutoFuzzException {
    SampleObject.testStaticMethodIntegerArray(array);
    (new SampleObject()).testMethodIntegerArray(array);
  }

  private void privateMethod(boolean bool) throws AutoFuzzException {
    SampleObject.testStaticMethodBoolean(bool);
    (new SampleObject()).testMethodBoolean(bool);
  }

  private void privateMethod(boolean[] array) throws AutoFuzzException {
    SampleObject.testStaticMethodBooleanArray(array);
    (new SampleObject()).testMethodBooleanArray(array);
  }
}
