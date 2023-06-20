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

package autofuzz.benchmark.object;

public class SampleObject extends SampleClass implements SampleInterface {
  @Override
  public void testInstanceMethod() {
    this.privateInstanceMethod();
  }

  @Override
  public void testInterfaceInstanceMethod() {
    this.privateInterfaceInstanceMethod();
  }

  public static void testClassMethod() {
    SampleObject.privateClassMethod();
  }

  public static void testInterfaceMethod() {
    SampleObject.privateInterfaceMethod();
  }

  public static SampleObject factoryMethod(){
    return new SampleObject();
  }

  public static void testStaticMethodString(String string) throws AutoFuzzException {
    SampleObject.testClassMethod();
    SampleObject.testInterfaceMethod();
  }

  public static void testStaticMethodInteger(Integer integer) throws AutoFuzzException {
    SampleObject.testClassMethod();
    SampleObject.testInterfaceMethod();
  }

  public static void testStaticMethodIntegerArray(int[] array) throws AutoFuzzException {
    SampleObject.testClassMethod();
    SampleObject.testInterfaceMethod();
  }

  public static void testStaticMethodIntegerArray(Integer[] array) throws AutoFuzzException {
    SampleObject.testClassMethod();
    SampleObject.testInterfaceMethod();
  }

  public static void testStaticMethodBoolean(Boolean bool) throws AutoFuzzException {
    SampleObject.testClassMethod();
    SampleObject.testInterfaceMethod();
  }

  public static void testStaticMethodBooleanArray(boolean[] array) throws AutoFuzzException {
    SampleObject.testClassMethod();
    SampleObject.testInterfaceMethod();
  }

  public static void testStaticMethodBooleanArray(Boolean[] array) throws AutoFuzzException {
    SampleObject.testClassMethod();
    SampleObject.testInterfaceMethod();
  }

  public static void testStaticMethodByte(Byte b) throws AutoFuzzException {
    SampleObject.testClassMethod();
    SampleObject.testInterfaceMethod();
  }

  public static void testStaticMethodByteArray(byte[] array) throws AutoFuzzException {
    SampleObject.testClassMethod();
    SampleObject.testInterfaceMethod();
  }

  public static void testStaticMethodByteArray(Byte[] array) throws AutoFuzzException {
    SampleObject.testClassMethod();
    SampleObject.testInterfaceMethod();
  }

  public static void testStaticMethodShort(Short sh) throws AutoFuzzException {
    SampleObject.testClassMethod();
    SampleObject.testInterfaceMethod();
  }

  public static void testStaticMethodShortArray(short[] array) throws AutoFuzzException {
    SampleObject.testClassMethod();
    SampleObject.testInterfaceMethod();
  }

  public static void testStaticMethodShortArray(Short[] array) throws AutoFuzzException {
    SampleObject.testClassMethod();
    SampleObject.testInterfaceMethod();
  }

  public static void testStaticMethodLong(Long l) throws AutoFuzzException {
    SampleObject.testClassMethod();
    SampleObject.testInterfaceMethod();
  }

  public static void testStaticMethodLongArray(long[] array) throws AutoFuzzException {
    SampleObject.testClassMethod();
    SampleObject.testInterfaceMethod();
  }

  public static void testStaticMethodLongArray(Long[] array) throws AutoFuzzException {
    SampleObject.testClassMethod();
    SampleObject.testInterfaceMethod();
  }

  public static void testStaticMethodFloat(Float fl) throws AutoFuzzException {
    SampleObject.testClassMethod();
    SampleObject.testInterfaceMethod();
  }

  public static void testStaticMethodCharacter(Character character) throws AutoFuzzException {
    SampleObject.testClassMethod();
    SampleObject.testInterfaceMethod();
  }

  public static void testStaticMethodObject(SampleObject object) throws AutoFuzzException {
    SampleObject.testClassMethod();
    SampleObject.testInterfaceMethod();
  }

  public static void testStaticMethodClass(Class<? extends Object> cl) throws AutoFuzzException {
    SampleObject.testClassMethod();
    SampleObject.testInterfaceMethod();
  }

  public static void testStaticMethodEnum(SampleEnum sampleEnum) throws AutoFuzzException {
    SampleObject.testClassMethod();
    SampleObject.testInterfaceMethod();
  }

  public void testMethodString(String string) throws AutoFuzzException {
    this.testInstanceMethod();
    this.testInterfaceInstanceMethod();
  }

  public void testMethodInteger(Integer integer) throws AutoFuzzException {
    this.testInstanceMethod();
    this.testInterfaceInstanceMethod();
  }

  public void testMethodIntegerArray(int[] array) throws AutoFuzzException {
    this.testInstanceMethod();
    this.testInterfaceInstanceMethod();
  }

  public void testMethodIntegerArray(Integer[] array) throws AutoFuzzException {
    this.testInstanceMethod();
    this.testInterfaceInstanceMethod();
  }

  public void testMethodBoolean(Boolean bool) throws AutoFuzzException {
    this.testInstanceMethod();
    this.testInterfaceInstanceMethod();
  }

  public void testMethodBooleanArray(boolean[] array) throws AutoFuzzException {
    this.testInstanceMethod();
    this.testInterfaceInstanceMethod();
  }

  public void testMethodBooleanArray(Boolean[] array) throws AutoFuzzException {
    this.testInstanceMethod();
    this.testInterfaceInstanceMethod();
  }

  public void testMethodByte(Byte b) throws AutoFuzzException {
    this.testInstanceMethod();
    this.testInterfaceInstanceMethod();
  }

  public void testMethodByteArray(byte[] array) throws AutoFuzzException {
    this.testInstanceMethod();
    this.testInterfaceInstanceMethod();
  }

  public void testMethodByteArray(Byte[] array) throws AutoFuzzException {
    this.testInstanceMethod();
    this.testInterfaceInstanceMethod();
  }

  public void testMethodShort(Short sh) throws AutoFuzzException {
    this.testInstanceMethod();
    this.testInterfaceInstanceMethod();
  }

  public void testMethodShortArray(short[] array) throws AutoFuzzException {
    this.testInstanceMethod();
    this.testInterfaceInstanceMethod();
  }

  public void testMethodShortArray(Short[] array) throws AutoFuzzException {
    this.testInstanceMethod();
    this.testInterfaceInstanceMethod();
  }

  public void testMethodLong(Long l) throws AutoFuzzException {
    this.testInstanceMethod();
    this.testInterfaceInstanceMethod();
  }

  public void testMethodLongArray(long[] array) throws AutoFuzzException {
    this.testInstanceMethod();
    this.testInterfaceInstanceMethod();
  }

  public void testMethodLongArray(Long[] array) throws AutoFuzzException {
    this.testInstanceMethod();
    this.testInterfaceInstanceMethod();
  }

  public void testMethodFloat(Float fl) throws AutoFuzzException {
    this.testInstanceMethod();
    this.testInterfaceInstanceMethod();
  }

  public void testMethodCharacter(Character character) throws AutoFuzzException {
    this.testInstanceMethod();
    this.testInterfaceInstanceMethod();
  }

  public void testMethodObject(SampleObject object) throws AutoFuzzException {
    this.testInstanceMethod();
    this.testInterfaceInstanceMethod();
  }

  public void testMethodClass(Class<? extends Object> cl) throws AutoFuzzException {
    this.testInstanceMethod();
    this.testInterfaceInstanceMethod();
  }

  public void testMethodEnum(SampleEnum sampleEnum) throws AutoFuzzException {
    this.testInstanceMethod();
    this.testInterfaceInstanceMethod();
  }

  private static void privateClassMethod() {
    (new SampleObject()).toString();
  }

  private static void privateInterfaceMethod() {
    (new SampleObject()).toString();
  }

  private void privateInstanceMethod() {
    this.toString();
  }

  private void privateInterfaceInstanceMethod() {
    this.toString();
  }
}
