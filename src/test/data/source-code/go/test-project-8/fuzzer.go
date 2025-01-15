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

package combined

import (
	"fmt"
	"strconv"
	"testing"
	"time"
)

type Shape struct {
	Type   string
	Radius float64
	Width  float64
	Height float64
}

func (s Shape) Area() float64 {
	if s.Type == "Circle" {
		return 3.14 * s.Radius * s.Radius
	} else if s.Type == "Rectangle" {
		return s.Width * s.Height
	}
	return 0
}

func (s Shape) Perimeter() float64 {
	if s.Type == "Circle" {
		return 2 * 3.14 * s.Radius
	} else if s.Type == "Rectangle" {
		return 2 * (s.Width + s.Height)
	}
	return 0
}

type Person struct {
	Name string
	Age  int
}

func (p Person) Greet() string {
	return fmt.Sprintf("Hello, my name is %s and I am %d years old.", p.Name, p.Age)
}

func (p Person) GoodBye() string {
	return fmt.Sprintf("Bye. See you next time.")
}

func unreachableGoroutine() {
	for i := 0; i < 5; i++ {
		processValue(i)
	}
}

func processValue(value int) {
	fmt.Printf("Processing value: %d\n", value)
}

func FuzzCombined(f *testing.F) {
	f.Fuzz(func(t *testing.T, radiusString, widthString, heightString, name string, ageString string) {
		radius, err := strconv.ParseFloat(radiusString, 64)
		if err != nil {
			return
		}

		width, err := strconv.ParseFloat(widthString, 64)
		if err != nil {
			return
		}

		height, err := strconv.ParseFloat(heightString, 64)
		if err != nil {
			return
		}

		age, err := strconv.Atoi(ageString)
		if err != nil {
			return
		}

		shapes := []Shape{
			{Type: "Circle", Radius: radius},
			{Type: "Rectangle", Width: width, Height: height},
		}

		p := Person{Name: name, Age: age}

		ch := make(chan string)
		go func() {
			ch <- p.Greet()
			for _, shape := range shapes {
				ch <- fmt.Sprintf("Shape: %s, Area: %.2f, Perimeter: %.2f", shape.Type, shape.Area(), shape.Perimeter())
			}
			close(ch)
		}()

		for msg := range ch {
			fmt.Println(msg)
		}

		for i := 0; i < len(shapes); i++ {
			fmt.Printf("Processing shape %d - Area: %.2f\n", i, shapes[i].Area())
		}
	})
}
