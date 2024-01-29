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
 * focus on the multiple layers of method calls with several logic branches. Auto-Fuzz
 * post-processing should be able to identify only one fuzzer that covers all other logic.
 *
 * <p>Target fuzzing method: public static Boolean parseData(String, Integer, Integer) throws
 * AutoFuzzException
 *
 * @author Fuzz Introspector
 */
public class Benchmark1 {
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
  public Benchmark1(String string) {
    this.data = string;
    this.parser = new SampleObject();
  }

  /**
   * This is the constructor of the benchmark.
   *
   * @param data the byte array which will transform to the main data string for parsing
   * @since 1.0
   */
  public Benchmark1(byte[] data) {
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
    Benchmark1 benchmark1 = new Benchmark1(string);
    return benchmark1.parseData(start, end);
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
    Character[] array = this.getCharacterArray(start, end);

    for (Character chr : array) {
      if (Character.isAlphabetic(chr)) {
        this.handleCharacter(chr);
      } else if (Character.isDigit(chr)) {
        this.handleNumber(chr);
      } else if (Character.isLetter(chr)) {
        this.handleByte(chr);
      } else {
        throw new AutoFuzzException("Invalid data.", new IllegalArgumentException());
      }
    }

    return true;
  }

  /**
   * Helpers method to retrieve the needed Chacater array for parsing.
   *
   * @param start the start index for string parsing
   * @param end the end index for string parsing
   * @return the resulting Character array
   * @throws AutoFuzzException if the input cannot be parsed
   * @since 1.0
   */
  public Character[] getCharacterArray(Integer start, Integer end) throws AutoFuzzException {
    if ((start < 0) || (end < start) || (end >= data.length())) {
      throw new AutoFuzzException("Invalid start and end index.", new IllegalArgumentException());
    }

    Character[] result = new Character[end - start + 1];
    char[] charArray = data.toCharArray();

    for (int i = start, j = 0; i <= end; i++, j++) {
      result[j] = Character.valueOf(charArray[i]);
    }

    return result;
  }

  /**
   * Helpers method for handling character.
   *
   * @param chr the character to handle
   * @throws AutoFuzzException if the input cannot be parsed
   * @since 1.0
   */
  public void handleCharacter(Character chr) throws AutoFuzzException {
    SampleObject.testStaticMethodCharacter(chr);
    parser.testMethodCharacter(chr);
  }

  /**
   * Helpers method for handling character in number format.
   *
   * @param chr the character to handle
   * @throws AutoFuzzException if the input cannot be parsed
   * @since 1.0
   */
  public void handleNumber(Character chr) throws AutoFuzzException {
    int value = Character.getNumericValue(chr);

    SampleObject.testStaticMethodShort((short) value);
    SampleObject.testStaticMethodInteger(value);
    SampleObject.testStaticMethodLong((long) value);
    SampleObject.testStaticMethodFloat((float) value);
    parser.testMethodShort((short) value);
    parser.testMethodInteger(value);
    parser.testMethodLong((long) value);
    parser.testMethodFloat((float) value);
  }

  /**
   * Helpers method for handling character in byte format.
   *
   * @param chr the character to handle
   * @throws AutoFuzzException if the input cannot be parsed
   * @since 1.0
   */
  public void handleByte(Character chr) throws AutoFuzzException {
    Byte value = Character.getDirectionality(chr);

    SampleObject.testStaticMethodByte(value);
    parser.testMethodByte(value);
  }

  public byte[] getDataByteArray() {
    return this.data.getBytes(Charset.defaultCharset());
  }

  public String getDataString() {
    return this.data;
  }
}
