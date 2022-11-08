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

public class BranchSide {
	private String trueSides;
	private List<String> trueSidesFuncs;
	private String falseSides;
	private List<String> falseSidesFuncs;

	public BranchSide() {
		this.trueSidesFuncs = new ArrayList<String>();
		this.falseSidesFuncs = new ArrayList<String>();
	}

	@JsonProperty("TrueSide")
	public String getTrueSides() {
		return trueSides;
	}

	public void setTrueSides(String trueSides) {
		this.trueSides = trueSides;	
	}

	@JsonProperty("TrueSideFuncs")
	public List<String> getTrueSidesFuncs() {
		return trueSidesFuncs;
	}

	public void addTrueSidesFuncs(String trueSidesFunc) {
		this.trueSidesFuncs.add(trueSidesFunc);
	}

	public void setTrueSidesFuncs(List<String> trueSidesFuncs) {
		this.trueSidesFuncs = trueSidesFuncs;
	}

	@JsonProperty("FalseSide")
	public String getFalseSides() {
		return falseSides;
	}

	public void setFalseSides(String falseSides) {
		this.falseSides = falseSides;
	}

	@JsonProperty("FalseSideFuncs")
	public List<String> getFalseSidesFuncs() {
		return falseSidesFuncs;
	}

	public void addFalseSidesFuncs(String falseSidesFunc) {
		this.falseSidesFuncs.add(falseSidesFunc);
	}

	public void setFalseSidesFuncs(List<String> falseSidesFuncs) {
		this.falseSidesFuncs = falseSidesFuncs;
	}
}
