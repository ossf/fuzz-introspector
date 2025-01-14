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

package structs

import (
	"testing"
	"fmt"
	"strconv"
)

type Person struct {
	Name string
	Age  int
}

func (p Person) Greet() string {
	return fmt.Sprintf("Hello, my name is %s and I am %d years old.", p.Name, p.Age)
}

type Dog struct {
	Name string
}

func (d Dog) Greet() string {
	return fmt.Sprintf("Hello, my dog's name is %s.", d.Name)
}

func FuzzStructs(f *testing.F) {
	f.Fuzz(func(t *testing.T, name string, ageString string) {
		age, err := strconv.Atoi(ageString)
		if err != nil {
			return
		}

		p := Person{Name: name, Age: age}
		_ = p.Greet()
	})
}

func (p Person) UnusedMethod() {
	fmt.Println("This method is never called")
}
