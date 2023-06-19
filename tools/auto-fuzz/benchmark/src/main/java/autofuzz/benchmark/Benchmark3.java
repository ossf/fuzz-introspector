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

public class Benchmark3 {
  private String data;
  private SampleObject parser;

  public Benchmark3(String string) {
    this.data = string;
    this.parser = new SampleObject();
  }

  public Benchmark3(byte[] data) {
    this(new String(data, Charset.defaultCharset()));
  }

  public static Boolean parseData(String string, Integer start, Integer end, String splitor)
      throws AutoFuzzException {
    Benchmark3 benchmark3 = new Benchmark3(string);
    return benchmark3.parseData(start, end, splitor);
  }

  public Boolean parseData(Integer start, Integer end, String splitor) throws AutoFuzzException {
    if ((start < 0) || (end < start) || (end >= this.data.length())) {
      throw new AutoFuzzException("Illegal start and end index.", new IllegalArgumentException());
    }

    this.parseString(this.data.substring(start, end), splitor);
    return true;
  }

  public String[] parseString(String string, String splitor) throws AutoFuzzException {
    return this.split(string, splitor);
  }

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
