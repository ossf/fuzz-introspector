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

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use syn::{Expr, ExprBlock, FnArg, ImplItem, ImplItemFn, Item, ItemFn, ItemImpl, ReturnType, Stmt, Visibility};
use syn::spanned::Spanned;

// Base struct for BranchSide array in Branch Profile
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BranchSide {
    #[serde(rename = "BranchSide")]
    pub branch_side: String,
    #[serde(rename = "BranchSideFuncs")]
    pub branch_side_funcs: Vec<String>,
}

// Base struct for Branch Profile elements
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BranchProfileEntry {
    #[serde(rename = "Branch String")]
    pub branch_string: String,
    #[serde(rename = "Branch Sides")]
    pub branch_sides: Vec<BranchSide>,
}

// Base struct for Callsites elements
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CallSite {
    #[serde(rename = "Src")]
    pub src: String,
    #[serde(rename = "Dst")]
    pub dst: String,
}

// Major struct for function elements
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FunctionInfo {
    #[serde(rename = "linkageType")]
    pub linkage_type: String,
    #[serde(rename = "constantsTouched")]
    pub constants_touched: Vec<String>,
    #[serde(rename = "argNames")]
    pub arg_names: Vec<String>,
    #[serde(rename = "functionName")]
    pub name: String,
    #[serde(rename = "functionSourceFile")]
    pub file: String,
    #[serde(rename = "returnType")]
    pub return_type: String,
    #[serde(rename = "argCount")]
    pub arg_count: usize,
    #[serde(rename = "argTypes")]
    pub arg_types: Vec<String>,
    #[serde(rename = "CyclomaticComplexity")]
    pub complexity: usize,
    #[serde(rename = "functionsReached")]
    pub called_functions: Vec<String>,
    #[serde(rename = "functionDepth")]
    pub depth: usize,
    pub visibility: String,
    #[serde(rename = "ICount")]
    pub icount: usize,
    #[serde(rename = "BBCount")]
    pub bbcount: usize,
    #[serde(rename = "EdgeCount")]
    pub edge_count: usize,
    #[serde(rename = "functionUses")]
    pub function_uses: usize,
    #[serde(rename = "BranchProfiles")]
    pub branch_profiles: Vec<BranchProfileEntry>,
    #[serde(rename = "functionLinenumber")]
    pub start_line: usize,
    #[serde(rename = "functionLinenumberEnd")]
    pub end_line: usize,
    #[serde(rename = "Callsites")]
    pub callsites: Vec<CallSite>,
}

// Helper struct to keep track of important information throughout the analysis
pub struct FunctionAnalyser {
    pub functions: Vec<FunctionInfo>,
    pub call_stack: HashMap<String, HashSet<String>>,
    pub reverse_call_map: HashMap<String, usize>,
    pub method_impls: HashMap<String, String>,
}

// Major implementation for the AST visiting and analysing through the syn crate
impl FunctionAnalyser {
    pub fn new() -> Self {
        Self {
            functions: Vec::new(),
            call_stack: HashMap::new(),
            reverse_call_map: HashMap::new(),
            method_impls: HashMap::new(),
        }
    }

    // Entry method to analyse rust source files and extract functions/methods definition
    pub fn analyse_file(&mut self, file_path: &str) -> std::io::Result<()> {
        // Parse the rust source code and build an AST by the syn crate
        let file_content = fs::read_to_string(&file_path)?;
        let syntax = syn::parse_file(&file_content)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        // Analyse and retrieve a list of functions/methods with all properties
        for item in syntax.items {
            match item {
                Item::Fn(func) => self.visit_function(&func, file_path),
                Item::Impl(ItemImpl { self_ty, items, .. }) => {
                    let parent_name =
                        format!("{}", quote::ToTokens::to_token_stream(&self_ty));
                    for impl_item in items {
                        if let ImplItem::Fn(method) = impl_item {
                            self.visit_method(&method, file_path, &parent_name);
                        }
                    }
                }
                _ => {}
            }
        }

        Ok(())
    }

    // visit implementation to go through all functions from the AST
    pub fn visit_function(&mut self, node: &ItemFn, file: &str) {
        let visibility = self.get_visibility(&node.vis);
        let (start_line, end_line) = self.get_function_lines(&node.block.brace_token);
        self.process_function(
            &node.sig.ident.to_string(),
            &node.sig.inputs,
            &node.sig.output,
            &node.block.stmts,
            file,
            visibility,
            start_line,
            end_line,
        );
    }

    // visit implementation to go through all methods from the AST
    pub fn visit_method(&mut self, node: &ImplItemFn, file: &str, parent_name: &str) {
        let name = format!("{}::{}", parent_name, node.sig.ident);
        self.method_impls
            .insert(node.sig.ident.to_string(), parent_name.to_string());
        let visibility = self.get_visibility(&node.vis);
        let (start_line, end_line) = self.get_function_lines(&node.block.brace_token);
        self.process_function(
            &name,
            &node.sig.inputs,
            &node.sig.output,
            &node.block.stmts,
            file,
            visibility,
            start_line,
            end_line,
        );
    }

    // Internal method to process each functions/methods when going through them in the AST
    // Used by visit_function and visit_method implementation
    fn process_function(
        &mut self,
        name: &str,
        inputs: &syn::punctuated::Punctuated<FnArg, syn::token::Comma>,
        output: &ReturnType,
        stmts: &[Stmt],
        file: &str,
        visibility: String,
        start_line: usize,
        end_line: usize,
    ) {
        // Discover return type of the target function/method
        let return_type = match output {
            ReturnType::Default => "void".to_string(),
            ReturnType::Type(_, ty) => format!("{}", quote::ToTokens::to_token_stream(&**ty)),
        }
        .replace(' ', "");

        // Discover the arg types Vector of the target function/method
        let arg_types = inputs
            .iter()
            .filter_map(|arg| {
                if let FnArg::Typed(pat) = arg {
                    Some(format!("{}", quote::ToTokens::to_token_stream(&*pat.ty)).replace(' ', ""))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        // Calculate the cyclomatic complexity of the target function/method
        let complexity = self.calculate_cyclomatic_complexity(stmts);

        // Calculate the basic block count of the target function/method
        let bbcount = stmts
            .iter()
            .filter(|stmt| matches!(stmt, Stmt::Expr(_, _) | Stmt::Local(_)))
            .count();

        // Calculate the edge count from the cyclomatic complexity and basic block count
        let edge_count = complexity + bbcount - 1;

        // Calculate the instruction (statements in rust) of the target function/method
        let icount = stmts.len();

        // Generate branch profiles for the target function/method. The SYN create AST
        // approach currently only support branching analysis for if statement.
        let branch_profiles = self.profile_branches(stmts, file);

        // Extract the callsites and called functions information from the target function/method
        let mut called_functions = Vec::new();
        let mut callsites = Vec::new();

        for stmt in stmts {
            self.extract_called_functions(stmt, &mut called_functions, &mut callsites, file);
        }

        called_functions.sort();
        called_functions.dedup();

        for called in &called_functions {
            *self.reverse_call_map.entry(called.clone()).or_insert(0) += 1;
        }

        // Store all infomration in the FunctionInfo struct for later yaml generation
        self.functions.push(FunctionInfo {
            linkage_type: String::new(),
            constants_touched: Vec::new(),
            arg_names: Vec::new(),
            name: name.to_string(),
            file: file.to_string(),
            return_type,
            arg_count: arg_types.len(),
            arg_types,
            complexity,
            called_functions: called_functions.clone(),
            depth: 0,
            visibility,
            icount,
            bbcount,
            edge_count,
            function_uses: 0,
            branch_profiles,
            start_line,
            end_line,
            callsites,
        });

        self.call_stack
            .entry(name.to_string())
            .or_default()
            .extend(called_functions.into_iter());
    }

    // Internal unboxing method implementation for unwrapping Stmt to Stmt::Expr and call extract_from_expr
    fn extract_called_functions(
        &self,
        stmt: &Stmt,
        called_functions: &mut Vec<String>,
        callsites: &mut Vec<CallSite>,
        file: &str,
    ) {
        if let Stmt::Expr(expr, _) = stmt {
            self.extract_from_expr(expr, called_functions, callsites, file);
        }
    }

    // Internal method implementation for extracting function/method called within different kind
    // of rust statement and expression. Only Expr::Call and Expr::MethodCall are he target
    // functions/methods that are expected in a callsites. All other expressions and statements are
    // decomposing to simplier statements and call either extract_called_functions or extract_from_expr
    // recursively to get down to the actual function/method calls in Expr::Call or Expr::MethodCall.
    fn extract_from_expr(
        &self,
        expr: &Expr,
        called_functions: &mut Vec<String>,
        callsites: &mut Vec<CallSite>,
        file: &str,
    ) {
        match expr {
            // General function call
            Expr::Call(call_expr) => {
                // Handle function call
                if let Expr::Path(path) = &*call_expr.func {
                    let full_path = path
                        .path
                        .segments
                        .iter()
                        .map(|seg| seg.ident.to_string())
                        .collect::<Vec<_>>()
                        .join("::");
                    called_functions.push(full_path.clone());
                    let span = call_expr.func.span().start();
                    callsites.push(CallSite {
                        src: format!("{},{},{}", file, span.line, span.column),
                        dst: full_path,
                    });
                }

                // Handle method/function in arguments
                for arg in &call_expr.args {
                    self.extract_from_expr(arg, called_functions, callsites, file);
                }
            }

            // General method call
            Expr::MethodCall(method_call) => {
                // Handle chained method/function
                self.extract_from_expr(
                    &method_call.receiver,
                    called_functions,
                    callsites,
                    file,
                );

                // Handle method call
                let method_name = method_call.method.to_string();
                if let Some(impl_name) = self.method_impls.get(&method_name) {
                    let full_path = format!("{}::{}", impl_name, method_name);
                    called_functions.push(full_path.clone());
                    let span = method_call.span().start();
                    callsites.push(CallSite {
                        src: format!("{},{},{}", file, span.line, span.column),
                        dst: full_path,
                    });
                }

                // Handle method/function in arguments
                for arg in &method_call.args {
                    self.extract_from_expr(arg, called_functions, callsites, file);
                }
            }

            // Basic block call
            Expr::Block(block_expr) => {
                for stmt in &block_expr.block.stmts {
                    match stmt {
                        Stmt::Local(local_stmt) => {
                            if let Some(init_expr) = &local_stmt.init {
                                self.extract_from_expr(&init_expr.expr, called_functions, callsites, file);
                            }
                        }

                        Stmt::Expr(expr, _) => {
                            self.extract_from_expr(expr, called_functions, callsites, file);
                        }

                        _ => {}
                    }
                }
            }

            // If statement
            Expr::If(if_expr) => {
                self.extract_from_expr(
                    &Expr::Block(ExprBlock {
                        attrs: Vec::new(),
                        label: None,
                        block: if_expr.then_branch.clone(),
                    }),
                    called_functions,
                    callsites,
                    file,
                );
                if let Some((_, else_expr)) = &if_expr.else_branch {
                    match else_expr.as_ref() {
                        // else if
                        Expr::If(_) => {
                            self.extract_from_expr(
                                else_expr,
                                called_functions,
                                callsites,
                                file,
                            );
                        }

                        // else
                        Expr::Block(block_expr) => {
                            self.extract_from_expr(
                                &Expr::Block(block_expr.clone()),
                                called_functions,
                                callsites,
                                file,
                            );
                        }

                        // For non-exhausive fail safe
                        _ => {}
                    }
                }
            }

            // Match statement
            Expr::Match(match_expr) => {
                for arm in &match_expr.arms {
                    self.extract_called_functions(
                        &Stmt::Expr(*arm.body.clone(), None),
                        called_functions,
                        callsites,
                        file,
                    );
                }
            }

            // Await statement
            Expr::Await(await_expr) => {
                self.extract_from_expr(&await_expr.base, called_functions, callsites, file);
            }

            // Try statment
            Expr::Try(try_expr) => {
                self.extract_from_expr(&try_expr.expr, called_functions, callsites, file);
            }

            // While loop
            Expr::While(while_expr) => {
                self.extract_from_expr(
                    &Expr::Block(ExprBlock {
                        attrs: Vec::new(),
                        label: None,
                        block: while_expr.body.clone(),
                    }),
                    called_functions,
                    callsites,
                    file,
                );
            }

            // For loop
            Expr::ForLoop(for_expr) => {
                self.extract_from_expr(
                    &Expr::Block(ExprBlock {
                        attrs: Vec::new(),
                        label: None,
                        block: for_expr.body.clone(),
                    }),
                    called_functions,
                    callsites,
                    file,
                );
            }

            // Closures inline
            Expr::Closure(closure) => {
                self.extract_called_functions(
                    &Stmt::Expr(*closure.body.clone(), None),
                    called_functions,
                    callsites,
                    file,
                );
            }

            // Struct context
            Expr::Struct(struct_expr) => {
                for field in &struct_expr.fields {
                    self.extract_from_expr(&field.expr, called_functions, callsites, file);
                }
            }

            // Indexing for vector and array
            Expr::Index(index_expr) => {
                self.extract_from_expr(&index_expr.expr, called_functions, callsites, file);
                self.extract_from_expr(&index_expr.index, called_functions, callsites, file);
            }

            // Impl field accessing
            Expr::Field(field_expr) => {
                self.extract_from_expr(&field_expr.base, called_functions, callsites, file);
            }

            // Tuple handling
            Expr::Tuple(tuple_expr) => {
                for elem in &tuple_expr.elems {
                    self.extract_from_expr(elem, called_functions, callsites, file);
                }
            }

            // Macro invocations
            Expr::Macro(macro_expr) => {
                if let Ok(parsed_body) = macro_expr.mac.parse_body::<Expr>() {
                    self.extract_from_expr(&parsed_body, called_functions, callsites, file);
                }
            }

            // Return statement
            Expr::Return(return_expr) => {
                if let Some(expr) = &return_expr.expr {
                    self.extract_from_expr(expr, called_functions, callsites, file);
                }
            }

            // Assigning statement
            Expr::Assign(assign_expr) => {
                self.extract_from_expr(&assign_expr.left, called_functions, callsites, file);
                self.extract_from_expr(&assign_expr.right, called_functions, callsites, file);
            }

            // Binary comparison
            Expr::Binary(binary_expr) => {
                self.extract_from_expr(&binary_expr.left, called_functions, callsites, file);
                self.extract_from_expr(&binary_expr.right, called_functions, callsites, file);
            }

            // Unary Comparison
            Expr::Unary(unary_expr) => {
                self.extract_from_expr(&unary_expr.expr, called_functions, callsites, file);
            }

            // Paren Statement
            Expr::Paren(paren_expr) => {
                self.extract_from_expr(&paren_expr.expr, called_functions, callsites, file);
            }

            // Grouping process
            Expr::Group(group_expr) => {
                self.extract_from_expr(&group_expr.expr, called_functions, callsites, file);
            }

            _ => {}
        }
    }

    // Transform Visibility enum of rust functions/methods into string
    fn get_visibility(&self, vis: &Visibility) -> String {
        match vis {
            Visibility::Public(_) => "public".to_string(),
            Visibility::Restricted(_) => "restricted".to_string(),
            Visibility::Inherited => "private".to_string(),
        }
    }

    // Internal helper for calculating cyclomatic complexity
    fn calculate_cyclomatic_complexity(&self, stmts: &[Stmt]) -> usize {
        1 + stmts.iter().filter(|stmt| matches!(stmt, Stmt::Expr(..))).count()
    }

    // Internal helper for retrieving the line number of the needed blocks/functions/lines
    // or other object with span information
    fn get_function_lines(&self, brace: &syn::token::Brace) -> (usize, usize) {
        let start = brace.span.open().start();
        let end = brace.span.close().end();
        (start.line, end.line)
    }

    // Internal helper method for extracing branch profile of a function
    // Currently, the SYN crate AST approach only support branching with IF statement
    // TODO Find other ways to extract and handle of other branching statements
    fn profile_branches(&self, stmts: &[Stmt], file: &str) -> Vec<BranchProfileEntry> {
        let mut branch_profiles = Vec::new();

        for stmt in stmts {
            match stmt {
                Stmt::Expr(Expr::If(if_expr), _) => {
                    let branch_string = format!(
                        "{}:{}:{}",
                        file,
                        if_expr.if_token.span.start().line,
                        if_expr.if_token.span.start().column
                    );

                    let mut branch_sides = vec![self.extract_branch_side(&if_expr.then_branch, file)];

                    if let Some((_, else_block)) = &if_expr.else_branch {
                        if let Expr::Block(block_expr) = &**else_block {
                            branch_sides.push(self.extract_branch_side(&block_expr.block, file));
                        }
                    }

                    branch_profiles.push(BranchProfileEntry {
                        branch_string,
                        branch_sides,
                    });
                }
                _ => {}
            }
        }

        branch_profiles
    }

    // Internal helper for profile_branches to retrieve information of the branch side for the if statement
    fn extract_branch_side(&self, block: &syn::Block, file: &str) -> BranchSide {
        let mut branch_side_funcs = vec![];
        for stmt in &block.stmts {
            self.extract_called_functions(stmt, &mut branch_side_funcs, &mut vec![], file);
        }

        let span = block.brace_token.span.open().start();
        let branch_side = format!("{}:{}:{}", file, span.line, span.column);

        BranchSide {
            branch_side,
            branch_side_funcs,
        }
    }

    // Public methods for post processing and fixing of called functions name to
    // include missing full qualified function name identifiers for impl methods
    pub fn post_process_called_functions(&mut self) {
        let function_set: HashSet<_> = self.functions.iter().map(|f| f.name.clone()).collect();

        for func in &mut self.functions {
            if let Some(impl_name) = func.name.split("::").next() {
                func.called_functions = func
                    .called_functions
                    .iter()
                    .map(|called| {
                        if !called.contains("::") {
                            let qualified_name = format!("{}::{}", impl_name, called);
                            if function_set.contains(&qualified_name) {
                                return qualified_name;
                            }
                        }
                        called.clone()
                    })
                    .collect();
            }

            func.function_uses = *self.reverse_call_map.get(&func.name).unwrap_or(&0);
        }
    }

    // Internal entry method for calculating function depth recursively
    fn calculate_function_depth(&self, name: &str) -> usize {
        let mut visited = HashSet::new();
        self.calculate_depth_recursive(name, &mut visited)
    }

    // Internal recursive method for tracing down the call tree
    // recursively to calculate the function/method call depth
    fn calculate_depth_recursive(&self, name: &str, visited: &mut HashSet<String>) -> usize {
        if !visited.insert(name.to_string()) {
            return 0;
        }

        if let Some(called_functions) = self.call_stack.get(name) {
            // Recursively called the called functions to determine the call depth
            let max_depth = called_functions
                .iter()
                .map(|callee| self.calculate_depth_recursive(callee, visited))
                .max()
                .unwrap_or(0);

            visited.remove(name);
            max_depth + 1
        } else {
            // Always return 0 for leaf function
            visited.remove(name);
            0
        }
    }

    // Public methods for calculating function depth, call to the
    // calculate_function_depth to start the recursion to determine the call depth
    pub fn calculate_depths(&mut self) {
        let depths: HashMap<String, usize> = self
            .functions
            .iter()
            .map(|function| {
                (
                    function.name.clone(),
                    self.calculate_function_depth(&function.name),
                )
            })
            .collect();

        for function in &mut self.functions {
            if let Some(&depth) = depths.get(&function.name) {
                function.depth = depth;
            }
        }
    }
}

// Main function for this module to analyse the given source directory and retrieve a list
// of FunctionInfo representing all functions/methods found in any rust source code located
// in the given directory, excluding a list of unrelated directories.
pub fn analyse_directory(dir: &str, exclude_dirs: &[&str]) -> std::io::Result<Vec<FunctionInfo>> {
    let mut analyser = FunctionAnalyser::new();

    // Search for rust source files and process
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let file_path = entry.path();

        if file_path.is_dir() && exclude_dirs.iter().any(|d| file_path.ends_with(d)) {
            continue;
        } else if file_path.is_dir() {
            let sub_result = analyse_directory(file_path.to_str().unwrap(), exclude_dirs)?;
            analyser.functions.extend(sub_result);
        } else if file_path.extension().and_then(|s| s.to_str()) == Some("rs") {
            analyser.analyse_file(file_path.to_str().unwrap())?;
        }
    }

    // Post process the result and add in additional information for each functions/methods
    analyser.calculate_depths();
    analyser.post_process_called_functions();

    Ok(analyser.functions)
}
