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

public class Heuristic9 {
  public final static Integer STATIC_METHOD_ONLY = 1;
  public final static Integer INSTANCE_METHOD_ONLY = 2;

  private Integer mode;

  private Heuristic9() {
    // Deny direct instance creation
  }

  public Heuristic9(Integer mode) {
    this.mode = mode;
  }

  public static Heuristic9 factory(Integer mode) {
    return new Heuristic9(mode);
  }

  public void testMethod(Float f) throws AutoFuzzException {
    this.privateMethod(f);
  }

  public void testMethod(Character character) throws AutoFuzzException {
    this.privateMethod(character);
  }

  private void privateMethod(Float f) throws AutoFuzzException {
    if (mode == Heuristic9.STATIC_METHOD_ONLY) {
      SampleObject.testStaticMethodFloat(f);
    } else if (mode == Heuristic9.INSTANCE_METHOD_ONLY) {
      (new SampleObject()).testMethodFloat(f);
    } else {
      throw new AutoFuzzException("Unsupported mode.", new IllegalStateException());
    }
  }

  private void privateMethod(Character character) throws AutoFuzzException {
    if (mode == Heuristic9.STATIC_METHOD_ONLY) {
      SampleObject.testStaticMethodCharacter(character);
    } else if (mode == Heuristic9.INSTANCE_METHOD_ONLY) {
      (new SampleObject()).testMethodCharacter(character);
    } else {
      throw new AutoFuzzException("Unsupported mode.", new IllegalStateException());
    }
  }

  class Heuristic9Factory {
    public Heuristic9 genHeuristic9(Integer mode) {
      return new Heuristic9(mode);
    }
  }
}
