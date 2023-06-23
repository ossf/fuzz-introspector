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
 * focus on the multiple layers of method calls with three entry methods recursive loop. Auto-Fuzz
 * post processing should be able to identify either one of the methods and include that in a fuzzer
 * and ignoring the remaining two as they created a recursive loop.
 *
 * <p>Target fuzzing methods (either one of them only): public void parseAlphabetic(String) throws
 * AutoFuzzException; public void parseInteger(String) throws AutoFuzzException; pulic void
 * parseFloat(String) throws AutoFuzzException
 *
 * @author Fuzz Introspector
 */
public class Benchmark5 {
  /** The sample object for method invocation */
  private SampleObject parser;

  /** The main list object to store the parse result */
  private List<Object> list;

  /**
   * This is the constructor of the benchmark.
   *
   * @since 1.0
   */
  public Benchmark5() {
    this.parser = new SampleObject();
    this.list = new LinkedList<Object>();
  }

  /**
   * One of the three entry methods included in the cross method recursive loop. This should be the
   * target method to be included and kept in the resulting fuzzer after Auto-Fuzz post processing
   * filter has been done. But only one of the three entry methods should be included in the result
   * while the other two should be filtered out.
   *
   * @param string the main data string for parsing
   * @throws AutoFuzzException if the input cannot be parsed
   * @since 1.0
   */
  public void parseAlphabetic(String string) throws AutoFuzzException {
    String result = "";

    for (int i = 0; i < string.length(); i++) {
      Character chr = string.charAt(i);
      if (Character.isAlphabetic(chr)) {
        result += string.charAt(i);
      } else if ((Character.isDigit(chr)) || chr.equals('-')) {
        if (result.length() > 0) {
          this.list.add(result);
        }
        this.parseInteger(string.substring(i));
        break;
      } else {
        throw new AutoFuzzException("Error in parsing.", new IllegalArgumentException());
      }
    }

    if (result.length() > 0) {
      this.list.add(result);
    }
  }

  /**
   * One of the three entry methods included in the cross method recursive loop. This should be the
   * target method to be included and kept in the resulting fuzzer after Auto-Fuzz post processing
   * filter has been done. But only one of the three entry methods should be included in the result
   * while the other two should be filtered out.
   *
   * @param string the main data string for parsing
   * @throws AutoFuzzException if the input cannot be parsed
   * @since 1.0
   */
  public void parseInteger(String string) throws AutoFuzzException {
    String result = "";

    for (int i = 0; i < string.length(); i++) {
      Character chr = string.charAt(i);
      if ((Character.isDigit(chr)) || chr.equals('-')) {
        result += string.charAt(i);
      } else if (chr.equals('.')) {
        this.parseFloat(string);
        break;
      } else if (Character.isAlphabetic(chr)) {
        if (result.length() > 0) {
          try {
            Integer number = Integer.parseInt(result);
            this.list.add(number);
          } catch (NumberFormatException e) {
            throw new AutoFuzzException("Error in parsing.", e);
          }
        }
        this.parseAlphabetic(string.substring(i));
        break;
      } else {
        throw new AutoFuzzException("Error in parsing.", new IllegalArgumentException());
      }
    }

    if (result.length() > 0) {
      try {
        Integer number = Integer.parseInt(result);
        this.list.add(number);
      } catch (NumberFormatException e) {
        throw new AutoFuzzException("Error in parsing.", e);
      }
    }
  }

  /**
   * One of the three entry methods included in the cross method recursive loop. This should be the
   * target method to be included and kept in the resulting fuzzer after Auto-Fuzz post processing
   * filter has been done. But only one of the three entry methods should be included in the result
   * while the other two should be filtered out.
   *
   * @param string the main data string for parsing
   * @throws AutoFuzzException if the input cannot be parsed
   * @since 1.0
   */
  public void parseFloat(String string) throws AutoFuzzException {
    String result = "";

    for (int i = 0; i < string.length(); i++) {
      Character chr = string.charAt(i);
      if ((Character.isDigit(chr)) || chr.equals('-') || chr.equals('.')) {
        result += string.charAt(i);
      } else if (Character.isAlphabetic(chr)) {
        if (result.length() > 0) {
          try {
            Float number = Float.parseFloat(result);
            this.list.add(number);
          } catch (NumberFormatException e) {
            throw new AutoFuzzException("Error in parsing.", e);
          }
        }
        this.parseAlphabetic(string.substring(i));
        break;
      } else {
        throw new AutoFuzzException("Error in parsing.", new IllegalArgumentException());
      }
    }

    if (result.length() > 0) {
      try {
        Float number = Float.parseFloat(result);
        this.list.add(number);
      } catch (NumberFormatException e) {
        throw new AutoFuzzException("Error in parsing.", e);
      }
    }
  }

  public List<Object> getList() {
    return this.list;
  }
}
