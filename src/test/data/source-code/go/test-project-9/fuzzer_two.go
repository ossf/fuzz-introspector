// Copyright 2025 Google LLC
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
//

package fuzzer

import (
	"fmt"
	"strconv"
	"testing"
)

func Multiply(a, b int) int {
	return a * b
}

func FuzzB(f *testing.F) {
	f.Fuzz(func(t *testing.T, aString, bString string) {
		a, err := strconv.Atoi(aString)
		if err != nil {
			return
		}

		b, err := strconv.Atoi(bString)
		if err != nil {
			return
		}

		result := Multiply(a, b)
		fmt.Printf("Multiplication Result: %d\n", result)

		SharedFunctionB(result)
	})
}

func unreachableMethodB() {
	fmt.Println("This method in module_b is unreachable.")
}

