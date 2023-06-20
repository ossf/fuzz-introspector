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
 * focus on the multiple layers of method calls with cross-methods recursion. Auto-Fuzz
 * post-processing should be able to identify only one fuzzer that covers all other logic.
 *
 * <p>Target fuzzing method: public static Boolean parseData(String, Integer, Integer, String)
 * throws AutoFuzzException
 *
 * @author Fuzz Introspector
 */
public class Benchmark3 {
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
  public Benchmark3(String string) {
    this.data = string;
    this.parser = new SampleObject();
  }

  /**
   * This is the constructor of the benchmark.
   *
   * @param data the byte array which will transform to the main data string for parsing
   * @since 1.0
   */
  public Benchmark3(byte[] data) {
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
   * @param splitor the string splitor to be used
   * @return if the parsing is success or not
   * @throws AutoFuzzException if the input cannot be parsed
   * @since 1.0
   */
  public static Boolean parseData(String string, Integer start, Integer end, String splitor)
      throws AutoFuzzException {
    Benchmark3 benchmark3 = new Benchmark3(string);
    return benchmark3.parseData(start, end, splitor);
  }

  /**
   * Main method to parse the string.
   *
   * @param start the start index for string parsing
   * @param end the end index for string parsing
   * @param splitor the string splitor to be used
   * @return if the parsing is success or not
   * @throws AutoFuzzException if the input cannot be parsed
   * @since 1.0
   */
  public Boolean parseData(Integer start, Integer end, String splitor) throws AutoFuzzException {
    if ((start < 0) || (end < start) || (end >= this.data.length())) {
      throw new AutoFuzzException("Illegal start and end index.", new IllegalArgumentException());
    }

    this.parseString(this.data.substring(start, end), splitor);
    return true;
  }

  /**
   * Two of the cross recursive methods.
   *
   * @param string the main data string for parsing
   * @param splitor the string splitor to be used
   * @return the splitted string array
   * @throws AutoFuzzException if the input cannot be parsed
   * @since 1.0
   */
  public String[] parseString(String string, String splitor) throws AutoFuzzException {
    return this.split(string, splitor);
  }

  /**
   * Two of the cross recursive methods.
   *
   * @param string the main data string for parsing
   * @param splitor the string splitor to be used
   * @return the splitted string array
   * @throws AutoFuzzException if the input cannot be parsed
   * @since 1.0
   */
  public String[] split(String string, String splitor) throws AutoFuzzException {
    if ((string == null)
        || (splitor == null)
        || (string.length() == 0)
        || (splitor.length() == 0)) {
      throw new AutoFuzzException("Illegal string or splitor", new IllegalArgumentException());
    }

    int index = string.indexOf(splitor);
    if (index != -1) {
      String first = string.substring(0, index);
      String second = string.substring(index + splitor.length());
      if (second.length() > 0) {
        String[] remaining = this.parseString(second, splitor);
        String[] result = new String[remaining.length + 1];
        result[0] = first;
        for (int i = 1; i < result.length; i++) {
          result[i] = remaining[i - 1];
        }
        return result;
      } else {
        return new String[] {first};
      }
    } else {
      return new String[] {string};
    }
  }

  public byte[] getDataByteArray() {
    return this.data.getBytes(Charset.defaultCharset());
  }

  public String getDataString() {
    return this.data;
  }
}
