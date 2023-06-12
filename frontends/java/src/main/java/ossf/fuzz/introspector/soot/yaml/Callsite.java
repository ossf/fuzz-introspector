// Copyright 2022 Fuzz Introspector Authors
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

package ossf.fuzz.introspector.soot.yaml;

import com.fasterxml.jackson.annotation.JsonProperty;

public class Callsite {
  private String source;
  private String methodName;

  @JsonProperty("Src")
  public String getSource() {
    return source;
  }

  public void setSource(String source) {
    this.source = source;
  }

  @JsonProperty("Dst")
  public String getMethodName() {
    return methodName;
  }

  public void setMethodName(String methodName) {
    this.methodName = methodName;
  }

  @Override
  public boolean equals(Object obj) {
    if (obj instanceof Callsite) {
      String selfMethodName = this.getMethodName();
      String objMethodName = ((Callsite) obj).getMethodName();
      return selfMethodName.equals(objMethodName);
    }
    return false;
  }
}
