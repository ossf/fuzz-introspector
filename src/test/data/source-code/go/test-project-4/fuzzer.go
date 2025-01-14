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

func (p Person) Introduce() string {
	return fmt.Sprintf("I am %s, a person of age %d.", p.Name, p.Age)
}

func (p Person) Describe() string {
	return fmt.Sprintf("Person: %s, Age: %d", p.Name, p.Age)
}

type Dog struct {
	Name string
}

func (d Dog) Greet() string {
	return fmt.Sprintf("Hello, my dog's name is %s.", d.Name)
}

func (d Dog) Introduce() string {
	return fmt.Sprintf("This is my dog, %s.", d.Name)
}

func (d Dog) Describe() string {
	return fmt.Sprintf("Dog: %s", d.Name)
}

func NewDog(name string) Dog {
	return Dog{Name: name}
}

type Robot struct {
	Model string
}

func (r Robot) Greet() string {
	return fmt.Sprintf("Hello, I am a robot of model %s.", r.Model)
}

func (r Robot) Introduce() string {
	return fmt.Sprintf("I am %s, a highly advanced robot.", r.Model)
}

func (r Robot) Describe() string {
	return fmt.Sprintf("Robot Model: %s", r.Model)
}

func FuzzStructs(f *testing.F) {
	f.Fuzz(func(t *testing.T, name string, ageString string, model string) {
		age, err := strconv.Atoi(ageString)
		if err != nil {
			return
		}

		personMap := map[int]Person{
			0: {Name: "Default", Age: 0},
			1: {Name: name, Age: age},
		}
		p := personMap[1]

		var dogInterface interface{} = Dog{Name: name}
		d, ok := dogInterface.(Dog)
		if !ok {
			return
		}

		d := NewDog(name)

		robots := [3]Robot{
			{Model: "X-1000"},
			{Model: "R2-D2"},
			{Model: model},
		}
		r := robots[0]

		_ = p.Greet()
		_ = d.Introduce()
		_ = r.Describe()
	})
}
