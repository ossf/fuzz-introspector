// Copyright 2025 Fuzz Introspector Authors
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
#![no_main]

pub mod math;

#[macro_use]
extern crate libfuzzer_sys;

use crate::math::{Adder, MyAdder};

macro_rules! double_add {
    ($adder:expr, $x:expr, $y:expr) => {
        $adder.add($x, $y) + $adder.add($x, $y)
    };
}

fuzz_target!(|data: &[u8]| {
    let adder = MyAdder {};
    if let Ok(n) = std::str::from_utf8(data).and_then(|s| s.parse::<i32>()) {
        let _ = unsafe { double_add!(adder, n, n) };
    }
});
