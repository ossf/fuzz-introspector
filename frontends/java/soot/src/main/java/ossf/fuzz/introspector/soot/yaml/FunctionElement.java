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

public class FunctionElement {
	private String functionName;
	private String functionSourceFile;
	private String linkageType;
	private Integer functionLinenumber;
	private Integer functionDepth;
	private String returnType;
	private Integer argCount;
	private List<String> argTypes;
	private List<String> constantsTouched;
	private List<String> argNames;
	private Integer BBCount;
	private Integer iCount;
	private Integer edgeCount;
	private Integer CyclomaticComplexity;
	private List<String> functionReached;
	private Integer functionUses;
	private BranchProfile branchProfiles;

	public FunctionElement() {
		this.argTypes = new ArrayList<String>();
		this.constantsTouched = new ArrayList<String>();
		this.argNames = new ArrayList<String>();
		this.functionReached = new ArrayList<String>();
	}

	public String getFunctionName() {
		return functionName;
	}

	public void setFunctionName(String functionName) {
		this.functionName = functionName;
	}

	public String getFunctionSourceFile() {
		return functionSourceFile;
	}

	public void setFunctionSourceFile(String functionSourceFile) {
		this.functionSourceFile = functionSourceFile;
	}

	public String getLinkageType() {
		return linkageType;
	}

	public void setLinkageType(String linkageType) {
		this.linkageType = linkageType;
	}

	public Integer getFunctionLinenumber() {
		return functionLinenumber;
	}

	public void setFunctionLinenumber(Integer functionLinenumber) {
		this.functionLinenumber = functionLinenumber;
	}

	public Integer getFunctionDepth() {
		return functionDepth;
	}

	public void setFunctionDepth(Integer functionDepth) {
		this.functionDepth = functionDepth;
	}

	public String getReturnType() {
		return returnType;
	}

	public void setReturnType(String type) {
		this.returnType = type;
	}

	public Integer getArgCount() {
		return argCount;
	}

	public void setArgCount(Integer argCount) {
		this.argCount = argCount;
	}

	public List<String> getArgTypes() {
		return argTypes;
	}

	public void addArgType(String argType) {
		this.argTypes.add(argType);
	}

	public void setArgTypes(List<String> list) {
		this.argTypes = list;
	}

	public List<String> getConstantsTouched() {
		return constantsTouched;
	}

	public void addConstantsTouched(String constantsTouched) {
		this.constantsTouched.add(constantsTouched);
	}

	public void setConstantsTouched(List<String> constantsTouched) {
		this.constantsTouched = constantsTouched;
	}

	public List<String> getArgNames() {
		return argNames;
	}

	public void addArgName(String argNames) {
		this.argNames.add(argNames);
	}

	public void setArgNames(List<String> argNames) {
		this.argNames = argNames;
	}

	public Integer getBBCount() {
		return BBCount;
	}

	public void setBBCount(Integer bBCount) {
		BBCount = bBCount;
	}

	public Integer getiCount() {
		return iCount;
	}

	public void setiCount(Integer iCount) {
		this.iCount = iCount;
	}

	public Integer getEdgeCount() {
		return edgeCount;
	}

	public void setEdgeCount(Integer edgeCount) {
		this.edgeCount = edgeCount;
	}

	public Integer getCyclomaticComplexity() {
		return CyclomaticComplexity;
	}

	public void setCyclomaticComplexity(Integer cyclomaticComplexity) {
		CyclomaticComplexity = cyclomaticComplexity;
	}

	public List<String> getFunctionReached() {
		return functionReached;
	}

	public void addFunctionReached(String functionReached) {
		this.functionReached.add(functionReached);
	}

	public void setFunctionReached(List<String> functionReached) {
		this.functionReached = functionReached;
	}

	public Integer getFunctionUses() {
		return functionUses;
	}

	public void setFunctionUses(Integer functionUses) {
		this.functionUses = functionUses;
	}

	public BranchProfile getBranchProfiles() {
		return branchProfiles;
	}

	public void setBranchProfiles(BranchProfile branchProfiles) {
		this.branchProfiles = branchProfiles;
	}
}
