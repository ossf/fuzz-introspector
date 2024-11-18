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

use crate::analyse::{CallSite, FunctionInfo};

use syn::{visit::Visit, Expr, ImplItem, ItemImpl, Macro, ExprMethodCall, ExprCall, ExprPath, Path as SynPath};
use syn::spanned::Spanned;

use std::collections::{HashSet, HashMap};
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::Path;

pub fn generate_call_trees(
    source_dir: &str,
    functions: &[FunctionInfo],
) -> io::Result<HashMap<String, FunctionInfo>> {
    // Retrieve a list of all fuzzing harnesses
    let fuzzing_files = find_fuzzing_harnesses(source_dir)?;
    let function_map: HashMap<String, &FunctionInfo> = functions.iter().map(|f| (f.name.clone(), f)).collect();

    let mut harness_map = HashMap::new();

    // Generate call graph per harness
    for fuzz_file in &fuzzing_files {
        let harness_name = Path::new(&fuzz_file)
            .file_stem()
            .unwrap()
            .to_string_lossy()
            .replace('_', "-");

        // Prepare initials
        let output_file = format!("fuzzerLogFile-{}.data", harness_name);
        let mut output = File::create(&output_file)?;

        writeln!(output, "Call tree")?;
        writeln!(output, "fuzz_target {} linenumber=-1", fuzz_file)?;

        // Extract functions from the fuzz_target macro in the harness
        let called_functions = extract_called_functions(fuzz_file)?;

        // Build the call tree
        let mut visited = HashSet::new();
        for (func_name, line_number) in &called_functions {
            if let Some(call_tree) = build_call_tree(
                &func_name,
                &function_map,
                fuzz_file,
                *line_number as i32,
                &mut visited,
                0,
            ) {
                output.write_all(call_tree.as_bytes())?;
            }
        }

        // Manually populate all fields for FunctionInfo
        let function_info = FunctionInfo {
            name: "fuzz_target".to_string(),
            file: fuzz_file.clone(),
            return_type: String::new(),
            linkage_type: String::new(),
            arg_count: 0,
            arg_names: Vec::new(),
            arg_types: Vec::new(),
            constants_touched: Vec::new(),
            called_functions: called_functions.iter().map(|(name, _)| name.clone()).collect(),
            branch_profiles: Vec::new(),
            callsites: called_functions
                .iter()
                .map(|(src, _)| CallSite {
                    src: fuzz_file.clone(),
                    dst: src.clone(),
                })
                .collect(),
            depth: 0,
            visibility: String::new(),
            icount: 0,
            bbcount: 0,
            edge_count: 0,
            complexity: 0,
            function_uses: 0,
            start_line: 0,
            end_line: 0,
        };
        harness_map.insert(fuzz_file.clone(), function_info);
    }

    Ok(harness_map)
}

// Locate all fuzzing harness files with fuzz_target macro
fn find_fuzzing_harnesses(dir: &str) -> io::Result<Vec<String>> {
    let mut harnesses = Vec::new();
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("rs") {
            let content = fs::read_to_string(&path)?;
            if content.contains("fuzz_target!") {
                harnesses.push(path.to_string_lossy().into_owned());
            }
        } else if path.is_dir() {
            harnesses.extend(find_fuzzing_harnesses(path.to_str().unwrap())?);
        }
    }
    Ok(harnesses)
}

// Extract all functions in the fuzz_target macro in the fuzzing harnesses
fn extract_called_functions(file_path: &str) -> io::Result<Vec<(String, usize)>> {
    let content = fs::read_to_string(file_path)?;
    let syntax = syn::parse_file(&content).expect("Failed to parse file");

    let mut visitor = FuzzTargetVisitor::default();
    visitor.visit_file(&syntax);
    Ok(visitor.called_functions)
}

// Base struct and syn:Visit implementation for traversing the function call tree
#[derive(Default)]
struct FuzzTargetVisitor {
    called_functions: Vec<(String, usize)>,
}

impl<'ast> Visit<'ast> for FuzzTargetVisitor {
    // visit implementation method for locating the statement in the fuzz_target macro
    fn visit_macro(&mut self, mac: &'ast Macro) {
        if mac.path.segments.last().unwrap().ident == "fuzz_target" {
            if let Ok(body) = mac.parse_body::<Expr>() {
                self.visit_expr(&body);
            }
        }
    }

    // visit implementation method for processing each function expression
    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        if let Expr::Path(ExprPath { path, .. }) = &*node.func {
            let qualified_name = path_to_string(path);
            let line_number = node.func.span().start().line;
            self.called_functions.push((qualified_name, line_number));
        }
        syn::visit::visit_expr_call(self, node);
    }

    // visit implementation method for handling echo method experssion
    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        let method_name = node.method.to_string();
        if let Expr::Path(ExprPath { path, .. }) = &*node.receiver {
            let receiver_name = path_to_string(path);
            let qualified_name = format!("{}::{}", receiver_name, method_name);
            let line_number = node.method.span().start().line;
            self.called_functions.push((qualified_name, line_number));
        }
        syn::visit::visit_expr_method_call(self, node);
    }

    // visit implementation method for handling other expressions
    fn visit_item_impl(&mut self, node: &'ast ItemImpl) {
        if let syn::Type::Path(type_path) = &*node.self_ty {
            let parent_name = path_to_string(&type_path.path);
            for item in &node.items {
                if let ImplItem::Fn(method) = item {
                    let method_name = format!("{}::{}", parent_name, method.sig.ident);
                    self.called_functions.push((method_name, 0));
                }
            }
        }
        syn::visit::visit_item_impl(self, node);
    }
}

// Process the correct full qualified name for rust functions/methods
fn path_to_string(path: &SynPath) -> String {
    path.segments
        .iter()
        .map(|s| s.ident.to_string())
        .collect::<Vec<_>>()
        .join("::")
}

// Build and output the call tree in .data format following LLVM approach
fn build_call_tree(
    function_name: &str,
    function_map: &HashMap<String, &FunctionInfo>,
    call_path: &str,
    mut line_number: i32,
    visited: &mut HashSet<String>,
    depth: usize,
) -> Option<String> {
    let mut result = String::new();

    // Only include functions/methods found in the project (determined from analysis result)
    if let Some(function_info) = find_function(function_name, function_map) {
        if visited.contains(&function_info.name) {
            return None;
        }

        visited.insert(function_info.name.clone());

        let indent = "  ".repeat(depth + 1);

        if line_number == 0 {
            line_number = -1;
        }

        // Insert the call tree line
        result.push_str(&format!(
            "{}{} {} linenumber={}\n",
            indent, function_info.name, call_path, line_number
        ));

        // Recursively process all function call trees
        for callsite in &function_info.callsites {
            let call_location: Vec<&str> = callsite.src.split(',').collect();
            if call_location.len() >= 2 {
                let callsite_path = call_location[0];
                let callsite_line = call_location[1].parse::<i32>().unwrap_or(-1);

                if let Some(call_tree) = build_call_tree(
                    &callsite.dst,
                    function_map,
                    callsite_path,
                    callsite_line,
                    visited,
                    depth + 1,
                ) {
                    result.push_str(&call_tree);
                }
            }
        }
    }

    if result.is_empty() {
        None
    } else {
        Some(result)
    }
}

// Search for the functions in the analysis result and exclude functions/methods not from the project
fn find_function<'a>(
    function_name: &str,
    function_map: &'a HashMap<String, &FunctionInfo>,
) -> Option<&'a FunctionInfo> {
    if let Some(func) = function_map.get(function_name) {
        return Some(func);
    }

    let simplified_name = function_name.split("::").last().unwrap_or(function_name);
    let mut best_match: Option<&FunctionInfo> = None;
    let mut best_match_length = 0;

    for func in function_map.values() {
        if func.name.ends_with(simplified_name) {
            let match_length = func.name.len();
            if match_length > best_match_length {
                best_match = Some(func);
                best_match_length = match_length;
            }
        }
    }

    best_match
}
