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

package channels

import (
	"fmt"
	"testing"
	"time"
)

type Square struct {
	Side float64
}

type Circle struct {
	Radius float64
}

func (s Square) Describe() string {
	return fmt.Sprintf("Square with side length %.2f", s.Side)
}

func (c Circle) Describe() string {
	return fmt.Sprintf("Circle with radius %.2f", c.Radius)
}

func unreachableGoroutine() {
	ch := make(chan Square)

	go func() {
		square := Square{Side: 4.0}
		ch <- square
		close(ch)
	}()

	for shape := range ch {
		fmt.Println(shape.Describe())
	}
}

func FuzzChannels(f *testing.F) {
	f.Fuzz(func(t *testing.T, durationString string) {
		duration, err := time.ParseDuration(durationString)
		if err != nil || duration < 0 {
			return
		}

		ch := make(chan Circle)

		go func() {
			time.Sleep(duration)
			circle := Circle{Radius: 5.5}
			ch <- circle
			close(ch)
		}()

		for shape := range ch {
			fmt.Println(shape.Describe())
		}
	})
}
