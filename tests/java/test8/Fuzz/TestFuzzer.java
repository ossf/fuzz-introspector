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

package Fuzz;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.api.CannedFuzzedDataProvider;

public class TestFuzzer {
	public static void fuzzerTestOneInput(FuzzedDataProvider data) {
		int choice = data.consumeInt(0,1);
		FunctionTest ft = new FunctionTest();

		if (choice == 0) {
			ft.function1();
		} else {
			ft.functionRecursion(data.consumeInt(-10,10));
		}
	}

	public static void main(String[] args) {
                TestFuzzer.fuzzerTestOneInput(new CannedFuzzedDataProvider("RANDOM"));
        }
}
