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

package shapes

import (
	"testing"
	"strconv"
)

type Shape interface {
	Area() float64
}

type Circle struct {
	Radius float64
}

func (c Circle) Area() float64 {
	return 3.14 * c.Radius * c.Radius
}

func (c Circle) Perimeter() float64 {
	return 2 * 3.14 * c.Radius
}

type Rectangle struct {
	Width, Height float64
}

func (r Rectangle) Area() float64 {
	return r.Width * r.Height
}

func (r Rectangle) Perimeter() float64 {
	return 2 * (r.Width + r.Height)
}

func FuzzShapes(f *testing.F) {
	f.Fuzz(func(t *testing.T, radiusString, widthString, heightString string) {
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

		shapes := []Shape{
			Circle{Radius: radius},
			Rectangle{Width: width, Height: height},
		}

		for _, shape := range shapes {
			_ = shape.Area()
		}

		for i := 0; i < len(shapes); i++ {
			_ = shapes[i].Perimeter()
		}
	})
}
