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

#[macro_use]
extern crate libfuzzer_sys;

fn unused_function() {
    let _ = unsafe { 42 };
}

fn reachable_function(data: &[u8]) -> Option<usize> {
    match data {
        [] => None,
        [_, ..] => Some(data.len()),
    }
}

fuzz_target!(|data: &[u8]| {
    let _ = reachable_function(data);
});
