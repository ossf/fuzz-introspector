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
////////////////////////////////////////////////////////////////////////////////

pub trait RecursiveTrait {
    fn process(&mut self, input: &str) -> String;
}

pub struct RecursiveStruct;

impl RecursiveStruct {
    pub fn new() -> Self {
        RecursiveStruct
    }
}

impl RecursiveTrait for RecursiveStruct {
    fn process(&mut self, input: &str) -> String {
        if input.is_empty() {
            String::new()
        } else {
            self.process(&input[1..])
        }
    }
}
