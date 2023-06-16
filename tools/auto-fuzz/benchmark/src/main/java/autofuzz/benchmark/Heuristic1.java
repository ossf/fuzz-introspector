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

public class Heuristic1 {
  public static void testHeuristic1(String string) throws AutoFuzzException {
    Heuristic1.testHeuristic1Inner(string);
  }

  public static void testHeuristic1(Integer integer) throws AutoFuzzException {
    Heuristic1.testHeuristic1Inner(integer);
  }

  public static void testHeuristic1(Integer[] array) throws AutoFuzzException {
    Heuristic1.testHeuristic1Inner(array);
  }

  public static void testHeuristic1Inner(String string) throws AutoFuzzException {
    Heuristic1.privateStaticMethod(string);
  }

  public static void testHeuristic1Inner(Integer integer) throws AutoFuzzException {
    Heuristic1.privateStaticMethod(integer);
  }

  public static void testHeuristic1Inner(Integer[] array) throws AutoFuzzException {
    Heuristic1.privateStaticMethod(array);
  }

  private static void privateStaticMethod(String string) throws AutoFuzzException {
    SampleObject.testStaticMethodString(string);
    (new SampleObject()).testMethodString(string);
  }

  private static void privateStaticMethod(Integer integer) throws AutoFuzzException {
    SampleObject.testStaticMethodInteger(integer);
    (new SampleObject()).testMethodInteger(integer);
  }

  private static void privateStaticMethod(Integer[] array) throws AutoFuzzException {
    SampleObject.testStaticMethodIntegerArray(array);
    (new SampleObject()).testMethodIntegerArray(array);
  }
}
