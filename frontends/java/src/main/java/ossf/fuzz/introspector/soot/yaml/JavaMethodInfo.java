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
  private Integer methodStatus;
  private Boolean isConcrete;
  private Boolean isJavaLibraryMethod;
  private Boolean isPublic;
  private Boolean isStatic;

  public JavaMethodInfo() {
    this.exceptions = new ArrayList<String>();
    this.isConcrete = true;
    this.isJavaLibraryMethod = false;
    this.isPublic = true;
    this.isStatic = false;
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
}
