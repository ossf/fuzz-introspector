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

mod analyse;
mod generate_yaml;
mod call_tree;

use std::io;

fn main() -> io::Result<()> {
    // Exclude unrelated directories
    let exclude_dirs = vec![
        "target",
        "node_modules",
        "aflplusplus",
        "tests",
        "examples",
        "benches",
        "honggfuzz",
        "inspector",
        "libfuzzer",
    ];

    // Obtain $SRC or given project source directory
    let args: Vec<String> = std::env::args().collect();
    let target_directory = if args.len() != 2 {
        match std::env::var("SRC") {
            Ok(src) => src,
            Err(_) => {
                eprintln!("Usage: cargo run -- <source_directory> or set the SRC environment variable");
                std::process::exit(1);
            }
        }
    } else {
        args[1].clone()
    };

    // Get the analysis result
    let functions = analyse::analyse_directory(&target_directory, &exclude_dirs)?;

    // Generate call trees for fuzzing harnesses and get their paths
    let fuzz_target_map = call_tree::generate_call_trees(&target_directory, &functions)?;

    // Generate YAML using the function list and fuzz target map
    generate_yaml::generate_yaml(&functions, &fuzz_target_map)?;

    Ok(())
}
