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

public class BranchProfile {
  private String branchString;
  private List<BranchSide> branchSides;

  public BranchProfile() {
    this.branchSides = new ArrayList<BranchSide>();
  }

  @JsonProperty("Branch String")
  public String getBranchString() {
    return branchString;
  }

  public void setBranchString(String branchString) {
    this.branchString = branchString;
  }

  @JsonProperty("Branch Sides")
  public List<BranchSide> getBranchSides() {
    return branchSides;
  }

  public void addBranchSides(BranchSide branchSide) {
    this.branchSides.add(branchSide);
  }

  public void setBranchSides(List<BranchSide> branchSides) {
    this.branchSides = branchSides;
  }
}
