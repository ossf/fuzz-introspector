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

public class Benchmark4 {
  public static final int FULL_PARSING = 1;
  public static final int FULL_REVERSE_PARSING = 2;
  public static final int PARIAL_PARSING = 3;
  public static final int PARTIAL_REVERSE_PARSING = 4;

  private String data;
  private SampleObject parser;

  public Benchmark4(String string) {
    this.data = string;
    this.parser = new SampleObject();
  }

  public Benchmark4(byte[] data) {
    this(new String(data, Charset.defaultCharset()));
  }

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

  public static String reverseString(String string) {
    String resultString = "";

    for (int i = 0; i < string.length(); i++) {
      resultString = string.charAt(i) + resultString;
    }

    return resultString;
  }

  public Boolean parseData(Integer start, Integer end) throws AutoFuzzException {
    if ((start < 0) || (end < start) || (end >= this.data.length())) {
      throw new AutoFuzzException("Illegal start and end index.", new IllegalArgumentException());
    }

    this.parseString(this.data.substring(start, end), "");
    return true;
  }

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
