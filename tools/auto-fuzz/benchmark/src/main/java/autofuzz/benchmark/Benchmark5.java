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
import java.util.*;

public class Benchmark5 {
  private SampleObject parser;
  private List<Object> list;

  public Benchmark5() {
    this.parser = new SampleObject();
    this.list = new LinkedList<Object>();
  }

  public void parseAlphabetic(String string) throws AutoFuzzException {
    String result = "";

    for (int i = 0;i<string.length();i++) {
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

  public void parseInteger(String string) throws AutoFuzzException {
    String result = "";

    for (int i = 0;i<string.length();i++) {
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

  public void parseFloat(String string) throws AutoFuzzException {
    String result = "";

    for (int i = 0;i<string.length();i++) {
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
