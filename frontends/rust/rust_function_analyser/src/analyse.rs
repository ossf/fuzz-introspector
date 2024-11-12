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

use syn::{ItemFn, Stmt, FnArg, ReturnType};
use std::collections::{HashMap, HashSet};
use serde::{Serialize, Deserialize};
use std::fs;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FunctionInfo {
    pub name: String,
    pub file: String,
    pub return_type: String,
    pub arg_count: usize,
    pub arg_types: Vec<String>,
    pub complexity: usize,
    pub called_functions: Vec<String>,
    pub depth: usize,
}

pub struct FunctionAnalyser {
    pub functions: Vec<FunctionInfo>,
    pub call_stack: HashMap<String, HashSet<String>>,
}

impl FunctionAnalyser {
    pub fn new() -> Self {
        Self {
            functions: Vec::new(),
            call_stack: HashMap::new(),
        }
    }

    pub fn visit_function(&mut self, node: &ItemFn, file_name: &str) {
        let function_name = node.sig.ident.to_string();
        let return_type = match &node.sig.output {
            ReturnType::Default => "void".to_string(),
            ReturnType::Type(_, ty) => format!("{}", quote::ToTokens::to_token_stream(&**ty)),
        }
        .replace(' ', "");

        let arg_types = node
            .sig
            .inputs
            .iter()
            .filter_map(|arg| {
                if let FnArg::Typed(pat) = arg {
                    Some(format!("{}", quote::ToTokens::to_token_stream(&*pat.ty)).replace(' ', ""))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        let complexity = calculate_cyclomatic_complexity(node);

        self.functions.push(FunctionInfo {
            name: function_name.clone(),
            file: file_name.to_string(),
            return_type,
            arg_count: arg_types.len(),
            arg_types,
            complexity,
            called_functions: vec![],
            depth: 0,
        });

        self.call_stack
            .entry(function_name.clone())
            .or_default();
    }

    pub fn calculate_depths(&mut self) {
        let mut depth_map: HashMap<String, usize> = HashMap::new();

        for function in &self.functions {
            let depth = self.calculate_function_depth(&function.name);
            depth_map.insert(function.name.clone(), depth);
        }

        for function in self.functions.iter_mut() {
            if let Some(&depth) = depth_map.get(&function.name) {
                function.depth = depth;
            }
        }
    }

    fn calculate_function_depth(
        &self,
        function_name: &str,
    ) -> usize {
        let mut max_depth = 0;
        let mut stack = vec![(function_name, 0)];

        while let Some((func, depth)) = stack.pop() {
            if depth > max_depth {
                max_depth = depth;
            }

            if let Some(called) = self.call_stack.get(func) {
                for callee in called {
                    if callee != func {
                        stack.push((callee, depth + 1));
                    }
                }
            }
        }

        max_depth
    }
}

fn calculate_cyclomatic_complexity(node: &ItemFn) -> usize {
    let mut complexity = 1;

    for stmt in &node.block.stmts {
        if matches!(stmt, Stmt::Expr(..)) {
            complexity += 1;
        }
    }

    complexity
}

pub fn analyse_directory(dir: &str, exclude_dirs: &[&str]) -> std::io::Result<String> {
    let mut analyser = FunctionAnalyser::new();

    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();

        if path.is_dir() && exclude_dirs.iter().any(|d| path.ends_with(d)) {
            continue;
        } else if path.is_dir() {
            let sub_result = analyse_directory(path.to_str().unwrap(), exclude_dirs)?;
            let parsed_functions: Vec<FunctionInfo> = serde_json::from_str(&sub_result).unwrap();
            analyser.functions.extend(parsed_functions);
        } else if path.extension().and_then(|s| s.to_str()) == Some("rs") {
            let file_content = fs::read_to_string(&path)?;
            let syntax = syn::parse_file(&file_content)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

            for item in syntax.items {
                if let syn::Item::Fn(func) = item {
                    analyser.visit_function(&func, path.to_str().unwrap());
                }
            }
        }
    }

    analyser.calculate_depths();
    Ok(serde_json::to_string(&analyser.functions).unwrap())
}
