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
import java.util.*;

/**
 * This is one of the benchmark classes for the Auto-Fuzz post-processing filter. This benchmark
 * focus on the multiple layers of method calls with a single entry method which loop and calls the
 * same method of a list of SampleObject instances. The real method invoked depends on the instance
 * type but the Auto-Fuzz post-processing should be able to identify either that unique entry method
 * which covers all methods in this benchmark.
 *
 * <p>Target fuzzing methods: public void parseData(String[]) throws AutoFuzzException
 *
 * @author Fuzz Introspector
 */
public class Benchmark6 {
  /** The sample object for method invocation */
  private List<SampleObject> list;

  /**
   * This is the constructor of the benchmark.
   *
   * @since 1.0
   */
  public Benchmark6(SampleObject object) {
    this.list = new LinkedList<SampleObject>();
    this.list.add(object);
  }

  /**
   * This is the constructor of the benchmark.
   *
   * @since 1.0
   */
  public Benchmark6(List<SampleObject> list) {
    this.list = list;
  }

  /**
   * Main method to parse a string with a list of SampleObject. This should be the only method
   * targeted by the fuzzers after post-processing of Auto-Fuzz.
   *
   * @param array the main data string array for parsing
   * @throws AutoFuzzException if the input cannot be parsed, or the number of string provided does
   *     not match with the number of SampleObject
   * @since 1.0
   */
  public void parseData(String[] array) throws AutoFuzzException {
    if (list.size() != array.length) {
      throw new AutoFuzzException(
          "Incorrect amount of array items", new IllegalArgumentException());
    }

    for (int i = 0; i < list.size(); i++) {
      SampleObject object = list.get(i);
      String string = array[i];
      object.testMethodString(string);
    }
  }

  /**
   * Static method to parse a string without creating the object instance.
   *
   * @param string the main data string for parsing
   * @return if the parsing is success or not
   * @throws AutoFuzzException if the input cannot be parsed
   * @since 1.0
   */
  public static Boolean parseData(String string) throws AutoFuzzException {
    Benchmark6.parseString(string, "");
    return true;
  }

  /**
   * Static method to parse a string without creating the object instance.
   *
   * @param string the main data string for parsing
   * @param start the start index for string parsing
   * @param end the end index for string parsing
   * @return if the parsing is success or not
   * @throws AutoFuzzException if the input cannot be parsed
   * @since 1.0
   */
  public static Boolean parseData(String string, Integer start, Integer end)
      throws AutoFuzzException {
    if ((start < 0) || (end < start) || (end >= string.length())) {
      throw new AutoFuzzException("Illegal start and end index.", new IllegalArgumentException());
    }

    Benchmark6.parseString(string.substring(start, end), "");
    return true;
  }

  /**
   * Recursive method to parse the string
   *
   * @param string the string to parse
   * @param indentation the indentation to add
   * @throws AutoFuzzException if the input cannot be parsed
   * @since 1.0
   */
  public static void parseString(String string, String indentation) throws AutoFuzzException {
    if (string.length() == 0) {
      return;
    }
    if (string.charAt(0) == '{') {
      Benchmark6.parseString(string.substring(1), indentation + " ");
    } else if (string.charAt(0) == '}') {
      Benchmark6.parseString(
          string.substring(1), indentation.substring(0, indentation.length() - 1));
    } else {
      SampleObject.testStaticMethodString(indentation.substring(1) + string.charAt(0));
      System.out.println(indentation.substring(1) + string.charAt(0));
      Benchmark6.parseString(string.substring(1), indentation);
    }
  }

  public List<SampleObject> getList() {
    return this.list;
  }

  class SampleObjectSubclass1 extends SampleObject {
    @Override
    public void testMethodString(String string) throws AutoFuzzException {
      super.testStaticMethodString(string);
      Benchmark6.parseData(string);
    }
  }

  class SampleObjectSubClass2 extends SampleObject {
    @Override
    public void testMethodString(String string) throws AutoFuzzException {
      super.testStaticMethodString(string);
      Benchmark6.parseData(string, 0, string.length() / 2 + 1);
    }
  }

  class SampleObjectSubClass3 extends SampleObjectSubclass1 {
    @Override
    public void testMethodString(String string) throws AutoFuzzException {
      super.testStaticMethodString(string);
      Benchmark6.parseString(string, "-");
    }
  }
}
