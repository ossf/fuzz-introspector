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

import com.fasterxml.jackson.annotation.JsonProperty;

public class ClassField {
  private String fieldName;
  private String fieldType;
  private Boolean isConcrete;
  private Boolean isPublic;
  private Boolean isStatic;
  private Boolean isFinal;

  @JsonProperty("Name")
  public String getFieldName() {
    return fieldName;
  }

  public void setFieldName(String fieldName) {
    this.fieldName = fieldName;
  }

  @JsonProperty("Type")
  public String getFieldType() {
    return fieldType;
  }

  public void setFieldType(String fieldType) {
    this.fieldType = fieldType;
  }

  @JsonProperty("concrete")
  public Boolean isConcrete() {
    return isConcrete;
  }

  public void setIsConcrete(Boolean isConcrete) {
    this.isConcrete = isConcrete;
  }

  @JsonProperty("public")
  public Boolean isPublic() {
    return isPublic;
  }

  public void setIsPublic(Boolean isPublic) {
    this.isPublic = isPublic;
  }

  @JsonProperty("static")
  public Boolean isStatic() {
    return isStatic;
  }

  public void setIsStatic(Boolean isStatic) {
    this.isStatic = isStatic;
  }

  @JsonProperty("final")
  public Boolean isFinal() {
    return isFinal;
  }

  public void setIsFinal(Boolean isFinal) {
    this.isFinal = isFinal;
  }
}
