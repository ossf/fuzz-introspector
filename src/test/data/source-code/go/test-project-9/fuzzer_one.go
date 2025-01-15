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

type Data struct {
	Value int
}

func (d Data) Increment() int {
	return d.Value + 1
}

func FuzzA(f *testing.F) {
	f.Fuzz(func(t *testing.T, input string) {
		num, err := strconv.Atoi(input)
		if err != nil {
			return
		}

		data := Data{Value: num}
		fmt.Printf("Incremented Value: %d\n", data.Increment())

		SharedFunctionA(num)
	})
}

func unreachableMethodA() {
	fmt.Println("This method in module_a is unreachable.")
}
