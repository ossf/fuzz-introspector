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

package ossf.fuzz.introspector.soot.yaml;

import java.util.ArrayList;
import java.util.List;

public class JavaMethodInfo {
  private List<String> exceptions;
  private List<String> interfaces;
  private List<ClassField> classFields;
  private List<String> argumentGenericTypes;
  private String returnValueGenericType;
  private String superClass;
  private Integer methodStatus;
  private Boolean isConcrete;
  private Boolean isJavaLibraryMethod;
  private Boolean isPublic;
  private Boolean isStatic;
  private Boolean isClassConcrete;
  private Boolean isClassEnum;
  private Boolean isClassPublic;

  public JavaMethodInfo() {
    this.exceptions = new ArrayList<String>();
    this.interfaces = new ArrayList<String>();
    this.classFields = new ArrayList<ClassField>();
    this.argumentGenericTypes = new ArrayList<String>();
    this.returnValueGenericType = "";
    this.superClass = "";
    this.isConcrete = true;
    this.isJavaLibraryMethod = false;
    this.isPublic = true;
    this.isStatic = false;
    this.isClassConcrete = true;
    this.isClassEnum = false;
    this.isClassPublic = true;
  }

  public List<String> getExceptions() {
    return this.exceptions;
  }

  public void addException(String exception) {
    this.exceptions.add(exception);
  }

  public void setExceptions(List<String> exceptions) {
    this.exceptions = exceptions;
  }

  public String getSuperClass() {
    return this.superClass;
  }

  public void setSuperClass(String superClass) {
    this.superClass = superClass;
  }

  public List<String> getInterfaces() {
    return this.interfaces;
  }

  public void addInterface(String interfaceName) {
    this.interfaces.add(interfaceName);
  }

  public void setInterfaces(List<String> interfaces) {
    this.interfaces = interfaces;
  }

  public List<ClassField> getClassFields() {
    return this.classFields;
  }

  public void addClassField(ClassField classField) {
    this.classFields.add(classField);
  }

  public void setClassFields(List<ClassField> classFields) {
    this.classFields = classFields;
  }

  public List<String> getArgumentGenericTypes() {
    return this.argumentGenericTypes;
  }

  public void setArgumentGenericTypes(List<String> argumentGenericTypes) {
    this.argumentGenericTypes = argumentGenericTypes;
  }

  public String getReturnValueGenericType() {
    return this.returnValueGenericType;
  }

  public void setReturnValueGenericType(String returnValueGenericType) {
    this.returnValueGenericType = returnValueGenericType;
  }

  public Boolean isConcrete() {
    return this.isConcrete;
  }

  public void setIsConcrete(Boolean isConcrete) {
    this.isConcrete = isConcrete;
  }

  public Boolean isJavaLibraryMethod() {
    return this.isJavaLibraryMethod;
  }

  public void setIsJavaLibraryMethod(Boolean isJavaLibraryMethod) {
    this.isJavaLibraryMethod = isJavaLibraryMethod;
  }

  public Boolean isPublic() {
    return this.isPublic;
  }

  public void setIsPublic(Boolean isPublic) {
    this.isPublic = isPublic;
  }

  public Boolean isStatic() {
    return this.isStatic;
  }

  public void setIsStatic(Boolean isStatic) {
    this.isStatic = isStatic;
  }

  public Boolean isClassConcrete() {
    return this.isClassConcrete;
  }

  public void setIsClassConcrete(Boolean isClassConcrete) {
    this.isClassConcrete = isClassConcrete;
  }

  public Boolean isClassEnum() {
    return this.isClassEnum;
  }

  public void setIsClassEnum(Boolean isClassEnum) {
    this.isClassEnum = isClassEnum;
  }

  public Boolean isClassPublic() {
    return this.isClassPublic;
  }

  public void setIsClassPublic(Boolean isClassPublic) {
    this.isClassPublic = isClassPublic;
  }
}
