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
import java.util.ArrayList;
import java.util.List;

public class FunctionConfig {
  private String listName;
  private List<FunctionElement> functionElements;

  public FunctionConfig() {
    this.functionElements = new ArrayList<FunctionElement>();
    this.listName = "All functions";
  }

  @JsonProperty("Function list name")
  public String getListName() {
    return listName;
  }

  public void setListName(String listName) {
    this.listName = listName;
  }

  @JsonProperty("Elements")
  public List<FunctionElement> getFunctionElements() {
    return functionElements;
  }

  public void setFunctionElements(List<FunctionElement> functionElements) {
    this.functionElements = new ArrayList<FunctionElement>();
    this.addFunctionElements(functionElements);
  }

  public void addFunctionElement(FunctionElement newElement) {
    FunctionElement oldElement = this.searchElement(newElement.getFunctionName());
    if (oldElement == null) {
      this.functionElements.add(newElement);
    }
  }

  public void addFunctionElements(List<FunctionElement> newElementList) {
    for (FunctionElement element : newElementList) {
      this.addFunctionElement(element);
    }
  }

  public FunctionElement searchElement(String functionName) {
    for (FunctionElement element : this.getFunctionElements()) {
      if (element.getFunctionName().equals(functionName)) {
        return element;
      }
    }
    return null;
  }
}
