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

    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: cargo run -- <source_directory>");
        std::process::exit(1);
    }
    let target_directory = &args[1];

    // Get the analysis result
    let functions = analyse::analyse_directory(target_directory, &exclude_dirs)?;

    // Generate call trees for fuzzing harnesses and get their paths
    let fuzzing_harnesses = call_tree::generate_call_trees(target_directory, &functions)?;

    // Generate YAML for each fuzzing harness
    generate_yaml::generate_yaml(&functions, &fuzzing_harnesses)?;

    Ok(())
}
