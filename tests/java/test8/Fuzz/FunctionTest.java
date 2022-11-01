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

public class FunctionTest {
	protected void function1() {
		System.out.println("F1");
	}

	protected void functionRecursion(int count) {
		if (count > 0) {
			System.out.println("In: " + count);
			this.functionRecursion(count-1);
			System.out.println("Out: " + count);
		} else {
			System.out.println("Deepest");
		}
	}

	protected void functionPublicDead() {
		System.out.println("PuD");
	}

	private void functionPrivateDead() {
		System.out.println("PrD");
	}

}
