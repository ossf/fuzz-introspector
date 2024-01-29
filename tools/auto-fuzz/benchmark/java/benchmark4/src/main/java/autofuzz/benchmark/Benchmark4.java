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
 * focus on the multiple layers of method calls with several logic branches. There are two entry
 * methods which will process some logic and then call each other if the wrong mode is used.
 * Auto-Fuzz post processing should be able to identify both of them as they have separate logic but
 * do call each other in some conditions.
 *
 * <p>Target fuzzing methods: public static Boolean parseData(String, Integer) throws
 * AutoFuzzException; public static Boolean parseData(String, Integer, Integer, Integer) throws
 * AutoFuzzException
 *
 * @author Fuzz Introspector
 */
public class Benchmark4 {
  public static final int FULL_PARSING = 1;
  public static final int FULL_REVERSE_PARSING = 2;
  public static final int PARIAL_PARSING = 3;
  public static final int PARTIAL_REVERSE_PARSING = 4;

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
  public Benchmark4(String string) {
    this.data = string;
    this.parser = new SampleObject();
  }

  /**
   * This is the constructor of the benchmark.
   *
   * @param data the byte array which will transform to the main data string for parsing
   * @since 1.0
   */
  public Benchmark4(byte[] data) {
    this(new String(data, Charset.defaultCharset()));
  }

  /**
   * Static method to parse a string without creating the object instance. This should be one of the
   * target methods to be included and kept in the resulting fuzzer after Auto-Fuzz post processing
   * filter has been done.
   *
   * @param string the main data string for parsing
   * @param mode the mode to be used
   * @return if the parsing is success or not
   * @throws AutoFuzzException if the input cannot be parsed
   * @since 1.0
   */
  public static Boolean parseData(String string, Integer mode) throws AutoFuzzException {
    Boolean result = true;

    switch (mode) {
      case Benchmark4.FULL_REVERSE_PARSING:
        string = Benchmark4.reverseString(string);
      case Benchmark4.FULL_PARSING:
        Benchmark4 benchmark4 = new Benchmark4(string);
        result = benchmark4.parseData(0, string.length());
        break;
      case Benchmark4.PARIAL_PARSING:
      case Benchmark4.PARTIAL_REVERSE_PARSING:
        result = Benchmark4.parseData(string, mode, 0, string.length());
        break;
      default:
        result = false;
    }

    if (result) {
      return true;
    }

    throw new AutoFuzzException("Error parsing string.", new IllegalArgumentException());
  }

  /**
   * Static method to parse a string without creating the object instance. This should be one of the
   * target methods to be included and kept in the resulting fuzzer after Auto-Fuzz post processing
   * filter has been done.
   *
   * @param string the main data string for parsing
   * @param mode the mode to be used
   * @param start the start index for string parsing
   * @param end the end index for string parsing
   * @return if the parsing is success or not
   * @throws AutoFuzzException if the input cannot be parsed
   * @since 1.0
   */
  public static Boolean parseData(String string, Integer mode, Integer start, Integer end)
      throws AutoFuzzException {
    Boolean result = true;

    switch (mode) {
      case Benchmark4.PARTIAL_REVERSE_PARSING:
        string = Benchmark4.reverseString(string);
      case Benchmark4.PARIAL_PARSING:
        Benchmark4 benchmark4 = new Benchmark4(string);
        result = benchmark4.parseData(start, end);
        break;
      case Benchmark4.FULL_PARSING:
      case Benchmark4.FULL_REVERSE_PARSING:
        result = Benchmark4.parseData(string, mode);
        break;
      default:
        result = false;
    }

    if (result) {
      return true;
    }

    throw new AutoFuzzException("Error parsing string.", new IllegalArgumentException());
  }

  /**
   * Helpers method to reverse the string before parsing.
   *
   * @param string the string to reverse
   * @return the resulting string
   * @since 1.0
   */
  public static String reverseString(String string) {
    String resultString = "";

    for (int i = 0; i < string.length(); i++) {
      resultString = string.charAt(i) + resultString;
    }

    return resultString;
  }

  /**
   * One of the two cross recursive methods to parse the string.
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
   * One of the two cross recursive methods to parse the string.
   *
   * @param start the start index for string parsing
   * @param end the end index for string parsing
   * @return if the parsing is success or not
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
