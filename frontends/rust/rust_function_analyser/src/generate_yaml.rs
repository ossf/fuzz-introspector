/* Copyright 2024 Fuzz Introspector Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use crate::analyse::FunctionInfo;

use serde::{Serialize, Deserialize};
use serde_yaml;

use std::fs::File;
use std::io::{self, Write};
use std::collections::HashMap;
use std::path::Path;

// Base struct for data.yaml files
#[derive(Serialize, Deserialize)]
struct FuzzerReport {
    #[serde(rename = "Fuzzer filename")]
    fuzzer_filename: String,
    #[serde(rename = "All functions")]
    all_functions: FunctionSection,
}

// Base struct for Functions array
#[derive(Serialize, Deserialize)]
struct FunctionSection {
    #[serde(rename = "Function list name")]
    function_list_name: String,
    #[serde(rename = "Elements")]
    elements: Vec<FunctionInfo>,
}

pub fn generate_yaml(functions: &[FunctionInfo], fuzz_target_map: &HashMap<String, FunctionInfo>) -> io::Result<()> {
    // Generate YAML per fuzzing harness
    for (harness, fuzz_target_info) in fuzz_target_map {
        let harness_name = Path::new(harness)
            .file_stem()
            .unwrap()
            .to_string_lossy()
            .replace('_', "-");

        // Append the specific fuzz target's FunctionInfo to the full function list
        let mut all_functions = functions.to_vec();
        all_functions.push(fuzz_target_info.clone());

        // Create the complete function report
        let report = FuzzerReport {
            fuzzer_filename: harness.clone(),
            all_functions: FunctionSection {
                function_list_name: "All functions".to_string(),
                elements: all_functions,
            },
        };

        // Convert and save to YAML file
        let yaml_data = serde_yaml::to_string(&report).expect("Failed to serialize YAML");
        let yaml_file_name = format!("fuzzerLogFile-{}.data.yaml", harness_name);
        let mut file = File::create(&yaml_file_name)?;
        file.write_all(yaml_data.as_bytes())?;
    }

    Ok(())
}
