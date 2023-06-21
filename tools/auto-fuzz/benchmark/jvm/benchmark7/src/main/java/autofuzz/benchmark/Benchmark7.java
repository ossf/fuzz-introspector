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
import java.lang.reflect.Method;
import java.util.*;

/**
 * This is one of the benchmark classes for the Auto-Fuzz post-processing filter. This benchmark
 * focus on invoking methods in the SampleObject with Java Reflection. Auto-Fuzz post-processing
 * should be able to identify only one fuzzer that covers all other logic.
 *
 * <p>Target fuzzing method: public static Boolean processClass(Class<? extends SampleObject>,
 * String, Integer) throws AutoFuzzException
 *
 * @author Fuzz Introspector
 */
public class Benchmark7 {
  /** The sample object for method invocation */
  private List<SampleObject> list;

  /**
   * This is the constructor of the benchmark.
   *
   * @since 1.0
   */
  public Benchmark7() {
    this.list = new LinkedList<SampleObject>();
  }

  /**
   * This is the constructor of the benchmark.
   *
   * @since 1.0
   */
  public Benchmark7(SampleObject object) {
    this.list = new LinkedList<SampleObject>();
    this.list.add(object);
  }

  /**
   * This is the constructor of the benchmark.
   *
   * @since 1.0
   */
  public Benchmark7(List<SampleObject> list) {
    this.list = list;
  }

  /**
   * Method to invoke specific methods of all the saved SampleObbject with given string input and
   * integer input. This should be the target method to be included and kept in the resulting fuzzer
   * after Auto-Fuzz post-processing filter has been done.
   *
   * @param objectClass the object class reference to search for needed methods
   * @param stringInput the string used for the process
   * @param integerInput the integer used for the process
   * @return if the process is success or not
   * @throws AutoFuzzException if the process and method invocation is failed
   * @since 1.0
   */
  public Boolean processClass(
      Class<? extends SampleObject> objectClass, String stringInput, Integer integerInput)
      throws AutoFuzzException {
    try {
      for (Method method : objectClass.getDeclaredMethods()) {
        for (SampleObject object : this.list) {
          if (method.getName().equals("testMethodString")) {
            method.invoke(object, stringInput);
          }
          if (method.getName().equals("testMethodInteger")) {
            method.invoke(object, integerInput);
          }
        }
      }
    } catch (Throwable e) {
      throw new AutoFuzzException("Error.", e);
    }

    return true;
  }

  /**
   * Static recursive method to parse the string
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

  class SampleObjectSubclass extends SampleObject {
    @Override
    public void testMethodString(String string) throws AutoFuzzException {
      super.testStaticMethodString(string);
      Benchmark7.parseString(string, "-");
    }

    @Override
    public void testMethodInteger(Integer integer) throws AutoFuzzException {
      super.testStaticMethodInteger(integer);
      Benchmark7.parseString(integer.toString(), "-");
    }
  }
}
