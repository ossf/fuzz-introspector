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
import java.util.Iterator;
import java.util.List;
import soot.SootClass;
import soot.SootField;
import soot.SootMethod;
import soot.Type;
import soot.Unit;

public class FunctionElement {
  private String functionName;
  private String functionSourceFile;
  private String linkageType;
  private Integer functionLinenumber;
  private Integer functionLinenumberEnd;
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
  private List<String> functionsReached;
  private Integer functionUses;
  private List<BranchProfile> branchProfiles;
  private List<Callsite> callsites;
  private JavaMethodInfo javaMethodInfo;

  public FunctionElement() {
    this.argTypes = new ArrayList<String>();
    this.constantsTouched = new ArrayList<String>();
    this.argNames = new ArrayList<String>();
    this.functionsReached = new ArrayList<String>();
    this.branchProfiles = new ArrayList<BranchProfile>();
    this.callsites = new ArrayList<Callsite>();

    this.functionName = "";
    this.functionSourceFile = "";
    this.linkageType = "";
    this.returnType = "";

    this.functionLinenumber = -1;
    this.functionLinenumberEnd = -1;
    this.functionDepth = 0;
    this.argCount = 0;
    this.BBCount = 0;
    this.iCount = 0;
    this.edgeCount = 0;
    this.CyclomaticComplexity = 0;
    this.functionUses = 0;

    this.javaMethodInfo = new JavaMethodInfo();
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

  public Integer getFunctionLinenumberEnd() {
    return functionLinenumberEnd;
  }

  public void setFunctionLinenumberEnd(Integer functionLinenumberEnd) {
    this.functionLinenumberEnd = functionLinenumberEnd;
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

  @JsonProperty("BBCount")
  public Integer getBBCount() {
    return BBCount;
  }

  public void setBBCount(Integer bBCount) {
    BBCount = bBCount;
  }

  @JsonProperty("ICount")
  public Integer getiCount() {
    return iCount;
  }

  public void setiCount(Integer iCount) {
    this.iCount = iCount;
  }

  @JsonProperty("EdgeCount")
  public Integer getEdgeCount() {
    return edgeCount;
  }

  public void setEdgeCount(Integer edgeCount) {
    this.edgeCount = edgeCount;
  }

  @JsonProperty("CyclomaticComplexity")
  public Integer getCyclomaticComplexity() {
    return CyclomaticComplexity;
  }

  public void setCyclomaticComplexity(Integer cyclomaticComplexity) {
    CyclomaticComplexity = cyclomaticComplexity;
  }

  public List<String> getFunctionsReached() {
    return functionsReached;
  }

  public void addFunctionsReached(String functionsReached) {
    if (!this.functionsReached.contains(functionsReached)) {
      this.functionsReached.add(functionsReached);
    }
  }

  public void setFunctionsReached(List<String> functionsReached) {
    this.functionsReached = functionsReached;
  }

  public Integer getFunctionUses() {
    return functionUses;
  }

  public void setFunctionUses(Integer functionUses) {
    this.functionUses = functionUses;
  }

  @JsonProperty("BranchProfiles")
  public List<BranchProfile> getBranchProfiles() {
    return branchProfiles;
  }

  public void addBranchProfile(BranchProfile branchProfile) {
    this.branchProfiles.add(branchProfile);
  }

  public void setBranchProfiles(List<BranchProfile> branchProfiles) {
    this.branchProfiles = branchProfiles;
  }

  @JsonProperty("Callsites")
  public List<Callsite> getCallsites() {
    return callsites;
  }

  public void addCallsite(Callsite callsite) {
    this.addFunctionsReached(callsite.getMethodName());

    Boolean duplicate = false;
    for (Callsite item : this.callsites) {
      if (item.equals(callsite)) {
        duplicate = true;
      }
    }

    if (!duplicate) {
      this.callsites.add(callsite);
    }
  }

  public void setCallsites(List<Callsite> callsites) {
    this.callsites = callsites;
  }

  @JsonProperty("JavaMethodInfo")
  public JavaMethodInfo getJavaMethodInfo() {
    return this.javaMethodInfo;
  }

  public void setJavaMethodInfo(SootMethod m, boolean isAutoFuzz) {
    JavaMethodInfo methodInfo = new JavaMethodInfo();
    SootClass c = m.getDeclaringClass();

    // Base java method information
    methodInfo.setIsConcrete(m.isConcrete());
    methodInfo.setIsJavaLibraryMethod(m.isJavaLibraryMethod());
    methodInfo.setIsPublic(m.isPublic());
    methodInfo.setIsStatic(m.isStatic());
    methodInfo.setIsClassEnum(c.isEnum());
    methodInfo.setIsClassPublic(c.isPublic());
    methodInfo.setIsClassConcrete(c.isConcrete());

    // Additional information for auto-fuzz process
    if (isAutoFuzz) {
      for (SootClass exception : m.getExceptions()) {
        methodInfo.addException(exception.getFilePath());
      }

      // Extra class information for constructors
      if (m.getName().equals("<init>")) {
        if (c.hasSuperclass()) {
          methodInfo.setSuperClass(c.getSuperclass().getName());
        }
        Iterator<SootClass> interfaces = c.getInterfaces().snapshotIterator();
        while (interfaces.hasNext()) {
          methodInfo.addInterface(interfaces.next().getName());
        }
        Iterator<SootField> fields = c.getFields().snapshotIterator();
        while (fields.hasNext()) {
          SootField field = fields.next();
          ClassField classField = new ClassField();

          classField.setFieldName(field.getName());
          classField.setFieldType(field.getType().toString());
          classField.setIsConcrete(field.isDeclared());
          classField.setIsPublic(field.isPublic());
          classField.setIsStatic(field.isStatic());
          classField.setIsFinal(field.isFinal());

          methodInfo.addClassField(classField);
        }
      }
    }

    this.javaMethodInfo = methodInfo;
  }

  public void setBaseInformation(SootMethod m) {
    SootClass c = m.getDeclaringClass();

    this.setFunctionSourceFile(c.getFilePath());
    this.setReturnType(m.getReturnType().toString());
    this.setFunctionDepth(0);
    this.setArgCount(m.getParameterCount());
    for (Type type : m.getParameterTypes()) {
      this.addArgType(type.toString());
    }

    Integer startLine = m.getJavaSourceStartLineNumber();
    Integer endLine = -1;
    if ((startLine > 0) && (m.hasActiveBody())) {
      for (Unit u : m.getActiveBody().getUnits()) {
        Integer line = u.getJavaSourceStartLineNumber();
        if (line > endLine) {
          endLine = line;
        }
      }
      if (endLine > 0) {
        endLine++;
      }
    }

    this.setFunctionLinenumber(startLine);
    this.setFunctionLinenumberEnd(endLine);
  }

  public void setCountInformation(Integer bbCount, Integer iCount, Integer complexity) {
    this.setBBCount(bbCount);
    this.setiCount(iCount);
    this.setCyclomaticComplexity(complexity);
  }
}
