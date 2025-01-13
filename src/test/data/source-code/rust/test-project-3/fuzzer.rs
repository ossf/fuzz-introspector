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

pub mod mod_a;
pub mod mod_b;

#[macro_use]
extern crate libfuzzer_sys;

use crate::mod_a::function_a;

macro_rules! is_uppercase {
    ($s:expr) => {
        $s.chars().all(|c| c.is_uppercase())
    };
}

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        match function_a(s).as_str() {
            "HELLO" => {},
            other if is_uppercase!(other) => {},
            _ => {}
        }
    }
});
