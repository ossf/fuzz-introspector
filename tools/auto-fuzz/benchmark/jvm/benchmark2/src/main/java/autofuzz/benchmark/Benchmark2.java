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
import java.nio.charset.Charset;

/**
 * This is one of the benchmark classes for the Auto-Fuzz post-processing filter. This benchmark
 * focus on the multiple layers of method calls with single method recursion. Auto-Fuzz
 * post-processing should be able to identify only one fuzzer that covers all other logic.
 *
 * <p>Target fuzzing method: public static Boolean parseData(String, Integer, Integer) throws
 * AutoFuzzException
 *
 * @author Fuzz Introspector
 */
public class Benchmark2 {
  /** The main data string for parsing */
  private String data;

  /** The sample object for method invocation */
  private SampleObject parser;

  /**
   * This is the constructor of the benchmark.
   *
   * @param string the main data string for parsing
   * @since 1.0
   */
  public Benchmark2(String string) {
    this.data = string;
    this.parser = new SampleObject();
  }

  /**
   * This is the constructor of the benchmark.
   *
   * @param data the byte array which will transform to the main data string for parsing
   * @since 1.0
   */
  public Benchmark2(byte[] data) {
    this(new String(data, Charset.defaultCharset()));
  }

  /**
   * Static method to parse a string without creating the object instance. This should be the target
   * method to be included and kept in the resulting fuzzer after Auto-Fuzz post processing filter
   * has been done.
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
    Benchmark2 benchmark2 = new Benchmark2(string);
    return benchmark2.parseData(start, end);
  }

  /**
   * Main method to parse the string.
   *
   * @param start the start index for string parsing
   * @param end the end index for string parsing
   * @return if the parsing is success or not
   * @throws AutoFuzzException if the input cannot be parsed
   * @since 1.0
   */
  public Boolean parseData(Integer start, Integer end) throws AutoFuzzException {
    if ((start < 0) || (end < start) || (end >= this.data.length())) {
      throw new AutoFuzzException("Illegal start and end index.", new IllegalArgumentException());
    }

    this.parseString(this.data.substring(start, end), "");
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
  public void parseString(String string, String indentation) throws AutoFuzzException {
    if (string.length() == 0) {
      return;
    }
    if (string.charAt(0) == '{') {
      parseString(string.substring(1), indentation + " ");
    } else if (string.charAt(0) == '}') {
      parseString(string.substring(1), indentation.substring(0, indentation.length() - 1));
    } else {
      SampleObject.testStaticMethodString(indentation.substring(1) + string.charAt(0));
      this.parser.testStaticMethodString(indentation.substring(1) + string.charAt(0));
      parseString(string.substring(1), indentation);
    }
  }

  public byte[] getDataByteArray() {
    return this.data.getBytes(Charset.defaultCharset());
  }

  public String getDataString() {
    return this.data;
  }
}
