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

pub trait Processor {
    fn complex_process(&mut self, input: &str) -> String;
}

pub struct CombinedStruct;

impl CombinedStruct {
    pub fn new() -> Self {
        CombinedStruct
    }
}

impl Processor for CombinedStruct {
    fn complex_process(&mut self, input: &str) -> String {
        if input.len() > 10 {
            input.to_uppercase()
        } else {
            self.complex_process(&(input.to_owned() + "x"))
        }
    }
}
