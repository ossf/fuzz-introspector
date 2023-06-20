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

package autofuzz.benchmark;

import autofuzz.benchmark.object.*;

/**
 * This is one of the benchmark classes for the Auto-Fuzz post-processing filter. This benchmark
 * focus on five different entry methods and call to a list of 52 methods. All the five entry method
 * together should cover all 52 methods. Thus Auto-Fuzz Auto-Fuzz post-processing should be able to
 * identify only those five entry methods and filter out the remaining methods.
 *
 * <p>Target fuzzing method: public void entry1(String) throws AutoFuzzException; public void
 * entry2(String) throws AutoFuzzException; public void entry3(String) throws AutoFuzzException;
 * public void entry4(String) throws AutoFuzzException; public void entry5(String) throws
 * AutoFuzzException;
 *
 * <p>Calling illustration for entry1: entry1 > method1 > method4 > method7 > method10 > method13 >
 * method16 > method19 > method22 > method25 > method28 > method31 > method34 > method37 > method40
 * > method43 > method46 > method49
 *
 * <p>Calling illustration for entry2: entry2 > method2 > method5 > method8 > method11 > method14 >
 * method17 > method20 > method23 > method26 > method29 > method32 > method35 > method38 > method41
 * > method44 > method47 > method50
 *
 * <p>Calling illustration for entry3: entry3 > method3 > method6 > method9 > method12 > method15 >
 * method18 > method21 > method24 > method27 > method30 > method33 > method36 > method39 > method42
 * > method45 > method48
 *
 * <p>Calling illustration for entry4: entry4 > methodPrime > method2 > method3 > method5 > method7
 * > method11 > method13 > method17 > method19 > method23 > method29 > method31 > method37 >
 * method41 > method43 > method47
 *
 * <p>Calling illustration for entry5: entry5 > methodSevenMultiply > method7 > method14 > method21
 * > method28 > method35 > method42 > method49
 *
 * @author Fuzz Introspector
 */
public class Benchmark8 {
  /**
   * One of the five entry methods calls down to all methods in the benchmark class. This should be
   * one of the target method to be included and kept in the resulting fuzzer after the Auto-Fuzz
   * post-processing filter has been done.
   *
   * @param string the string to process
   * @throws AutoFuzzException if the process and method invocation is failed
   * @since 1.0
   */
  public void entry1(String string) throws AutoFuzzException {
    this.method1(string, 1);
  }

  /**
   * One of the five entry methods calls down to all methods in the benchmark class. This should be
   * one of the target method to be included and kept in the resulting fuzzer after the Auto-Fuzz
   * post-processing filter has been done.
   *
   * @param string the string to process
   * @throws AutoFuzzException if the process and method invocation is failed
   * @since 1.0
   */
  public void entry2(String string) throws AutoFuzzException {
    this.method2(string, 2);
  }

  /**
   * One of the five entry methods calls down to all methods in the benchmark class. This should be
   * one of the target method to be included and kept in the resulting fuzzer after the Auto-Fuzz
   * post-processing filter has been done.
   *
   * @param string the string to process
   * @throws AutoFuzzException if the process and method invocation is failed
   * @since 1.0
   */
  public void entry3(String string) throws AutoFuzzException {
    this.method3(string, 3);
  }

  /**
   * One of the five entry methods calls down to all methods in the benchmark class. This should be
   * one of the target method to be included and kept in the resulting fuzzer after the Auto-Fuzz
   * post-processing filter has been done.
   *
   * @param string the string to process
   * @throws AutoFuzzException if the process and method invocation is failed
   * @since 1.0
   */
  public void entry4(String string) throws AutoFuzzException {
    this.methodPrime(string);
  }

  /**
   * One of the five entry methods calls down to all methods in the benchmark class. This should be
   * one of the target method to be included and kept in the resulting fuzzer after the Auto-Fuzz
   * post-processing filter has been done.
   *
   * @param string the string to process
   * @throws AutoFuzzException if the process and method invocation is failed
   * @since 1.0
   */
  public void entry5(String string) throws AutoFuzzException {
    this.methodSevenMultiply(string);
  }

  // The 52 methods that the Auto-Fuzz post-processing should filter out.
  public void methodPrime(String string) throws AutoFuzzException {
    this.method2(string, 4);
  }

  public void methodSevenMultiply(String string) throws AutoFuzzException {
    this.method7(string, 5);
  }

  public void method1(String string, Integer path) throws AutoFuzzException {
    this.method4(string, path);
  }

  public void method2(String string, Integer path) throws AutoFuzzException {
    if (path == 2) {
      this.method5(string, path);
    } else {
      this.method3(string, path);
    }
  }

  public void method3(String string, Integer path) throws AutoFuzzException {
    if (path == 3) {
      this.method6(string, path);
    } else {
      this.method5(string, path);
    }
  }

  public void method4(String string, Integer path) throws AutoFuzzException {
    this.method7(string, path);
  }

  public void method5(String string, Integer path) throws AutoFuzzException {
    if (path == 2) {
      this.method8(string, path);
    } else {
      this.method7(string, path);
    }
  }

  public void method6(String string, Integer path) throws AutoFuzzException {
    this.method9(string, path);
  }

  public void method7(String string, Integer path) throws AutoFuzzException {
    if (path == 1) {
      this.method10(string, path);
    } else if (path == 4) {
      this.method11(string, path);
    } else {
      this.method14(string, path);
    }
  }

  public void method8(String string, Integer path) throws AutoFuzzException {
    this.method11(string, path);
  }

  public void method9(String string, Integer path) throws AutoFuzzException {
    this.method12(string, path);
  }

  public void method10(String string, Integer path) throws AutoFuzzException {
    this.method13(string, path);
  }

  public void method11(String string, Integer path) throws AutoFuzzException {
    if (path == 2) {
      this.method14(string, path);
    } else {
      this.method13(string, path);
    }
  }

  public void method12(String string, Integer path) throws AutoFuzzException {
    this.method15(string, path);
  }

  public void method13(String string, Integer path) throws AutoFuzzException {
    if (path == 1) {
      this.method16(string, path);
    } else {
      this.method17(string, path);
    }
  }

  public void method14(String string, Integer path) throws AutoFuzzException {
    if (path == 2) {
      this.method17(string, path);
    } else {
      this.method21(string, path);
    }
  }

  public void method15(String string, Integer path) throws AutoFuzzException {
    this.method8(string, path);
  }

  public void method16(String string, Integer path) throws AutoFuzzException {
    this.method19(string, path);
  }

  public void method17(String string, Integer path) throws AutoFuzzException {
    if (path == 2) {
      this.method20(string, path);
    } else {
      this.method19(string, path);
    }
  }

  public void method18(String string, Integer path) throws AutoFuzzException {
    this.method21(string, path);
  }

  public void method19(String string, Integer path) throws AutoFuzzException {
    if (path == 1) {
      this.method22(string, path);
    } else {
      this.method23(string, path);
    }
  }

  public void method20(String string, Integer path) throws AutoFuzzException {
    this.method23(string, path);
  }

  public void method21(String string, Integer path) throws AutoFuzzException {
    if (path == 3) {
      this.method24(string, path);
    } else {
      this.method28(string, path);
    }
  }

  public void method22(String string, Integer path) throws AutoFuzzException {
    this.method25(string, path);
  }

  public void method23(String string, Integer path) throws AutoFuzzException {
    if (path == 2) {
      this.method26(string, path);
    } else {
      this.method29(string, path);
    }
  }

  public void method24(String string, Integer path) throws AutoFuzzException {
    this.method27(string, path);
  }

  public void method25(String string, Integer path) throws AutoFuzzException {
    this.method28(string, path);
  }

  public void method26(String string, Integer path) throws AutoFuzzException {
    this.method29(string, path);
  }

  public void method27(String string, Integer path) throws AutoFuzzException {
    this.method30(string, path);
  }

  public void method28(String string, Integer path) throws AutoFuzzException {
    if (path == 1) {
      this.method31(string, path);
    } else {
      this.method35(string, path);
    }
  }

  public void method29(String string, Integer path) throws AutoFuzzException {
    if (path == 2) {
      this.method32(string, path);
    } else {
      this.method31(string, path);
    }
  }

  public void method30(String string, Integer path) throws AutoFuzzException {
    this.method33(string, path);
  }

  public void method31(String string, Integer path) throws AutoFuzzException {
    if (path == 1) {
      this.method34(string, path);
    } else {
      this.method37(string, path);
    }
  }

  public void method32(String string, Integer path) throws AutoFuzzException {
    this.method35(string, path);
  }

  public void method33(String string, Integer path) throws AutoFuzzException {
    this.method36(string, path);
  }

  public void method34(String string, Integer path) throws AutoFuzzException {
    this.method37(string, path);
  }

  public void method35(String string, Integer path) throws AutoFuzzException {
    if (path == 2) {
      this.method38(string, path);
    } else {
      this.method42(string, path);
    }
  }

  public void method36(String string, Integer path) throws AutoFuzzException {
    this.method39(string, path);
  }

  public void method37(String string, Integer path) throws AutoFuzzException {
    if (path == 1) {
      this.method40(string, path);
    } else {
      this.method41(string, path);
    }
  }

  public void method38(String string, Integer path) throws AutoFuzzException {
    this.method41(string, path);
  }

  public void method39(String string, Integer path) throws AutoFuzzException {
    this.method42(string, path);
  }

  public void method40(String string, Integer path) throws AutoFuzzException {
    this.method43(string, path);
  }

  public void method41(String string, Integer path) throws AutoFuzzException {
    if (path == 2) {
      this.method44(string, path);
    } else {
      this.method43(string, path);
    }
  }

  public void method42(String string, Integer path) throws AutoFuzzException {
    if (path == 3) {
      this.method45(string, path);
    } else {
      this.method49(string, path);
    }
  }

  public void method43(String string, Integer path) throws AutoFuzzException {
    if (path == 1) {
      this.method46(string, path);
    } else {
      this.method47(string, path);
    }
  }

  public void method44(String string, Integer path) throws AutoFuzzException {
    this.method47(string, path);
  }

  public void method45(String string, Integer path) throws AutoFuzzException {
    this.method48(string, path);
  }

  public void method46(String string, Integer path) throws AutoFuzzException {
    this.method49(string, path);
  }

  public void method47(String string, Integer path) throws AutoFuzzException {
    if (path == 2) {
      this.method50(string, path);
    } else {
      SampleObject.testStaticMethodString(string);
    }
  }

  public void method48(String string, Integer path) throws AutoFuzzException {
    SampleObject.testStaticMethodString(string);
  }

  public void method49(String string, Integer path) throws AutoFuzzException {
    SampleObject.testStaticMethodString(string);
  }

  public void method50(String string, Integer path) throws AutoFuzzException {
    SampleObject.testStaticMethodString(string);
  }
}
