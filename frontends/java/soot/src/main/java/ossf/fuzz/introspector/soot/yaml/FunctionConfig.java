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

import java.util.ArrayList;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonProperty;

public class FunctionConfig {
	private String listName;
	private List<FunctionElement> functionElements;

	public FunctionConfig() {
		this.functionElements = new ArrayList<FunctionElement>();
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

	public void addFunctionElement(FunctionElement functionElement) {
		this.functionElements.add(functionElement);
	}

	public void setFunctionElements(List<FunctionElement> functionElements) {
		this.functionElements = functionElements;
	}
}
