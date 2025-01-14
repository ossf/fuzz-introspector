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

pub mod utils;

#[macro_use]
extern crate libfuzzer_sys;

use crate::utils::call_with;
use crate::utils::process_str;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let len = unsafe { call_with(s, |x| x.len()) };
        let _ = match len {
            0 => "Empty input",
            _ => process_str(s);,
        };
    }
});
