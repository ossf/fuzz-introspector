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
use syn::{
    punctuated::Punctuated, spanned::Spanned, Expr, ExprBlock, FnArg, ImplItemFn, Item,
    ItemFn, Pat, ReturnType, Stmt, Visibility
};

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
    pub method_return_types: HashMap<(String, String), String>,
    pub variable_types: HashMap<String, String>,
    pub first_pass_complete: bool,
}

// Major implementation for the AST visiting and analysing through the syn crate
impl FunctionAnalyser {
    pub fn new() -> Self {
        Self {
            functions: Vec::new(),
            call_stack: HashMap::new(),
            reverse_call_map: HashMap::new(),
            method_return_types: HashMap::new(),
            variable_types: HashMap::new(),
            first_pass_complete: false,
        }
    }

    // Entry method to analyse rust source files and extract functions/methods definition
    pub fn analyse_file(&mut self, file_path: &str) -> std::io::Result<()> {
        // Parse the rust source code and build an AST by the syn crate
        let file_content = fs::read_to_string(&file_path)?;
        let syntax = syn::parse_file(&file_content)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        // Analyse and retrieve a list of functions/methods return value and impl for processing
        self.first_pass_complete = false;
        for item in &syntax.items {
            match item {
                syn::Item::Fn(item_fn) => self.visit_function(item_fn, file_path),
                syn::Item::Impl(item_impl) => {
                    if let syn::Type::Path(type_path) = &*item_impl.self_ty {
                        let impl_type = type_path.path.segments.last().unwrap().ident.to_string();
                        for item in &item_impl.items {
                            if let syn::ImplItem::Fn(method) = item {
                                self.visit_method(method, file_path, &impl_type);
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        // Second pass to handle functions/methods call and process them directly
        self.first_pass_complete = true;
        for item in &syntax.items {
            match item {
                syn::Item::Fn(item_fn) => self.visit_function(item_fn, file_path),
                syn::Item::Impl(item_impl) => {
                    if let syn::Type::Path(type_path) = &*item_impl.self_ty {
                        let impl_type = type_path.path.segments.last().unwrap().ident.to_string();
                        for item in &item_impl.items {
                            if let syn::ImplItem::Fn(method) = item {
                                self.visit_method(method, file_path, &impl_type);
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        Ok(())
    }

    // visit implementation to go through all functions from the AST in two passes approach
    pub fn visit_function(&mut self, node: &ItemFn, file: &str) {
        self.extract_parameter_types(&node.sig.inputs);

        if !self.first_pass_complete {
            if let syn::ReturnType::Type(_, ty) = &node.sig.output {
                if let syn::Type::Path(type_path) = &**ty {
                    let function_name = node.sig.ident.to_string();
                    let return_type = type_path.path.segments.last().unwrap().ident.to_string();
                    self.method_return_types.insert(("".to_string(), function_name), return_type);
                }
            }
        } else {
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
            self.variable_types.clear();
        }
    }

    // visit implementation to go through all methods from the AST
    pub fn visit_method(&mut self, node: &ImplItemFn, file: &str, parent_name: &str) {
        let method_name = format!("{}::{}", parent_name, node.sig.ident);

        if !self.first_pass_complete {
            let return_type = match &node.sig.output {
                syn::ReturnType::Type(_, ty) => match &**ty {
                    syn::Type::Path(type_path) => type_path
                        .path
                        .segments
                        .last()
                        .map(|seg| seg.ident.to_string()),
                    _ => None,
                },
                syn::ReturnType::Default => None,
            };

            if let Some(return_type) = return_type {
                self.method_return_types
                    .insert((parent_name.to_string(), method_name), return_type);
            }
        } else {
            self.extract_parameter_types(&node.sig.inputs);
            let visibility = self.get_visibility(&node.vis);
            let (start_line, end_line) = self.get_function_lines(&node.block.brace_token);
            self.process_function(
                &method_name,
                &node.sig.inputs,
                &node.sig.output,
                &node.block.stmts,
                file,
                visibility,
                start_line,
                end_line,
            );
        }
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
        // Clean function/method name
        let cleaned_name = self.clean_function_name(name.to_string());

        // Discover return type of the target function/method
        let return_type = match output {
            ReturnType::Default => "void".to_string(),
            ReturnType::Type(_, ty) => {
                let mut return_type = self.clean_function_name(format!("{}", quote::ToTokens::to_token_stream(&**ty)));
                if cleaned_name.contains("::") && return_type == "Self" {
                    if let Some(pos) = name.rfind("::") {
                        return_type = name[..pos].to_string();
                    }
                }
                return_type
            }
        };

        // Discover the arg types Vector of the target function/method
        let arg_types = inputs
            .iter()
            .filter_map(|arg| {
                if let FnArg::Typed(pat) = arg {
                    Some(format!("{}", self.clean_function_name(quote::ToTokens::to_token_stream(&*pat.ty).to_string())))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        // Discover the arg names Vector of the target function/method
        let arg_names = inputs
            .iter()
            .filter_map(|arg| {
                if let FnArg::Typed(pat) = arg {
                    if let Pat::Ident(ident) = &*pat.pat {
                        Some(ident.ident.to_string())
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        // Mapping of argument name and type
        let arg_map: HashMap<String, String> = arg_names
            .clone()
            .into_iter()
            .zip(arg_types.clone().into_iter())
            .collect();

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
        let branch_profiles = self.profile_branches(stmts, file, &arg_map);

        // Extract the callsites and called functions information from the target function/method
        let mut called_functions = Vec::new();
        let mut callsites = Vec::new();

        for stmt in stmts {
            self.extract_called_functions(stmt, &mut called_functions, &mut callsites, file, &arg_map);
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
            arg_names,
            name: cleaned_name,
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
        arg_map: &HashMap<String, String>,
    ) {
        match stmt {
            Stmt::Local(local_stmt) => {
                if let Some(init_expr) = &local_stmt.init {

                    self.extract_from_expr(&init_expr.expr, called_functions, callsites, file, arg_map);
                }
            }

            Stmt::Item(item) => {
                if let Item::Fn(item_fn) = item {
                    for stmt in &item_fn.block.stmts {
                        self.extract_called_functions(stmt, called_functions, callsites, file, arg_map);
                    }
                }
            }

            Stmt::Expr(expr, _) => {
                self.extract_from_expr(expr, called_functions, callsites, file, arg_map);
            }

            Stmt::Macro(macro_stmt) => {
                if let Ok(parsed_body) = macro_stmt.mac.parse_body::<Expr>() {
                    self.extract_from_expr(&parsed_body, called_functions, callsites, file, arg_map);
                }
            }
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
        arg_map: &HashMap<String, String>,
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
                    called_functions.push(self.clean_function_name(full_path.clone()));
                    let span = call_expr.func.span().start();
                    callsites.push(CallSite {
                        src: format!("{},{},{}", file, span.line, span.column),
                        dst: self.clean_function_name(full_path),
                    });
                }

                // Handle method/function in arguments
                for arg in &call_expr.args {
                    self.extract_from_expr(arg, called_functions, callsites, file, arg_map);
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
                    arg_map,
                );

                // Determine correct method impl
                let receiver_type = self.extract_receiver_type(&method_call.receiver);
                let method_name = method_call.method.to_string();
                let resolved_type = match receiver_type.as_deref() {
                    Some(typ) => Some(typ.to_string()),
                    None => {
                        if let Expr::Path(path) = &*method_call.receiver {
                            if let Some(ident) = path.path.get_ident() {
                                arg_map.get(&ident.to_string()).cloned()
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    }
                };

                let full_path = match resolved_type {
                    Some(receiver) => format!("{}::{}", receiver, method_name),
                    None => method_name.clone(),
                };

                // Store called functions/methods
                called_functions.push(self.clean_function_name(full_path.clone()));
                let span = method_call.span().start();
                callsites.push(CallSite {
                    src: format!("{},{},{}", file, span.line, span.column),
                    dst: self.clean_function_name(full_path),
                });

                // Handle method/function in arguments
                for arg in &method_call.args {
                    self.extract_from_expr(arg, called_functions, callsites, file, arg_map);
                }
            }

            // Basic block call
            Expr::Block(block_expr) => {
                for stmt in &block_expr.block.stmts {
                    match stmt {
                        Stmt::Local(local_stmt) => {
                            if let Some(init_expr) = &local_stmt.init {
                                self.extract_from_expr(&init_expr.expr, called_functions, callsites, file, arg_map);
                            }
                        }

                        Stmt::Expr(expr, _) => {
                            self.extract_from_expr(expr, called_functions, callsites, file, arg_map);
                        }

                        _ => {}
                    }
                }
            }

            // If statement
            Expr::If(if_expr) => {
                self.extract_from_expr(
                    &if_expr.cond,
                    called_functions,
                    callsites,
                    file,
                    arg_map);
                self.extract_from_expr(
                    &Expr::Block(ExprBlock {
                        attrs: Vec::new(),
                        label: None,
                        block: if_expr.then_branch.clone(),
                    }),
                    called_functions,
                    callsites,
                    file,
                    arg_map,
                );
                if let Some((_, else_expr)) = &if_expr.else_branch {
                    self.extract_from_expr(
                        else_expr,
                        called_functions,
                        callsites,
                        file,
                        arg_map,
                    );
                }
            }

            // Match statement
            Expr::Match(match_expr) => {
                self.extract_from_expr(&match_expr.expr, called_functions, callsites, file, arg_map);

                for arm in &match_expr.arms {
                    self.extract_called_functions(
                        &Stmt::Expr(*arm.body.clone(), None),
                        called_functions,
                        callsites,
                        file,
                        arg_map,
                    );
                }
            }

            // Await statement
            Expr::Await(await_expr) => {
                self.extract_from_expr(&await_expr.base, called_functions, callsites, file, arg_map);
            }

            // Async block
            Expr::Async(async_expr) => {
                for stmt in &async_expr.block.stmts {
                    self.extract_called_functions(stmt, called_functions, callsites, file, arg_map);
                }
            }

            // Try block
            Expr::TryBlock(try_block_expr) => {
                for stmt in &try_block_expr.block.stmts {
                    self.extract_called_functions(stmt, called_functions, callsites, file, arg_map);
                }
            }

            // Try statment
            Expr::Try(try_expr) => {
                self.extract_from_expr(&try_expr.expr, called_functions, callsites, file, arg_map);
            }

            // While loop
            Expr::While(while_expr) => {
                self.extract_from_expr(&while_expr.cond, called_functions, callsites, file, arg_map);

                self.extract_from_expr(
                    &Expr::Block(ExprBlock {
                        attrs: Vec::new(),
                        label: None,
                        block: while_expr.body.clone(),
                    }),
                    called_functions,
                    callsites,
                    file,
                    arg_map,
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
                    arg_map,
                );
            }

            // Infinite loop
            Expr::Loop(loop_expr) => {
                for stmt in &loop_expr.body.stmts {
                    self.extract_called_functions(stmt, called_functions, callsites, file, arg_map);
                }
            }

            // Closures inline
            Expr::Closure(closure) => {
                self.extract_called_functions(
                    &Stmt::Expr(*closure.body.clone(), None),
                    called_functions,
                    callsites,
                    file,
                    arg_map,
                );
            }

            // Struct context
            Expr::Struct(struct_expr) => {
                for field in &struct_expr.fields {
                    self.extract_from_expr(&field.expr, called_functions, callsites, file, arg_map);
                }
                if let Some(rest_expr) = &struct_expr.rest {
                    self.extract_from_expr(rest_expr, called_functions, callsites, file, arg_map);
                }
            }

            // Indexing for vector and array
            Expr::Index(index_expr) => {
                self.extract_from_expr(&index_expr.expr, called_functions, callsites, file, arg_map);
                self.extract_from_expr(&index_expr.index, called_functions, callsites, file, arg_map);
            }

            // Impl field accessing
            Expr::Field(field_expr) => {
                self.extract_from_expr(&field_expr.base, called_functions, callsites, file, arg_map);
            }

            // Tuple handling
            Expr::Tuple(tuple_expr) => {
                for elem in &tuple_expr.elems {
                    self.extract_from_expr(elem, called_functions, callsites, file, arg_map);
                }
            }

            // Macro invocations
            Expr::Macro(macro_expr) => {
                if let Ok(parsed_body) = macro_expr.mac.parse_body::<Expr>() {
                    self.extract_from_expr(&parsed_body, called_functions, callsites, file, arg_map);
                }
            }

            // Return statement
            Expr::Return(return_expr) => {
                if let Some(expr) = &return_expr.expr {
                    self.extract_from_expr(expr, called_functions, callsites, file, arg_map);
                }
            }

            // Assigning statement
            Expr::Assign(assign_expr) => {
                self.extract_from_expr(&assign_expr.left, called_functions, callsites, file, arg_map);
                self.extract_from_expr(&assign_expr.right, called_functions, callsites, file, arg_map);
            }

            // Binary comparison
            Expr::Binary(binary_expr) => {
                self.extract_from_expr(&binary_expr.left, called_functions, callsites, file, arg_map);
                self.extract_from_expr(&binary_expr.right, called_functions, callsites, file, arg_map);
            }

            // Unary Comparison
            Expr::Unary(unary_expr) => {
                self.extract_from_expr(&unary_expr.expr, called_functions, callsites, file, arg_map);
            }

            // Unsafe Block
            Expr::Unsafe(unsafe_expr) => {
                for stmt in &unsafe_expr.block.stmts {
                    self.extract_called_functions(stmt, called_functions, callsites, file, arg_map);
                }
            }

            // Paren Statement
            Expr::Paren(paren_expr) => {
                self.extract_from_expr(&paren_expr.expr, called_functions, callsites, file, arg_map);
            }

            // Grouping process
            Expr::Group(group_expr) => {
                self.extract_from_expr(&group_expr.expr, called_functions, callsites, file, arg_map);
            }

            _ => {}
        }
    }

    // Helper method to determine correcct parameter type for method call impl discovery
    fn extract_parameter_types(&mut self, inputs: &Punctuated<syn::FnArg, syn::token::Comma>) {
        for input in inputs {
            if let syn::FnArg::Typed(pat_type) = input {
                if let syn::Pat::Ident(pat_ident) = &*pat_type.pat {
                    let variable_name = pat_ident.ident.to_string();
                    let variable_type = match &*pat_type.ty {
                        syn::Type::Path(type_path) => type_path
                            .path
                            .segments
                            .last()
                            .map(|seg| seg.ident.to_string()),
                        _ => None,
                    };
                    if let Some(var_type) = variable_type {
                        self.variable_types.insert(variable_name, var_type);
                    }
                }
            }
        }
    }

    // Helper method to determine correct receiver type of a method call
    fn extract_receiver_type(&self, receiver: &syn::Expr) -> Option<String> {
        match receiver {
            // For variable or parameter calls
            Expr::Path(path_expr) => {
                let variable_name = path_expr.path.segments.last()?.ident.to_string();
                self.variable_types.get(&variable_name).cloned()
            }

            // For chained calls
            Expr::MethodCall(method_call) => {
                let receiver_type = self.extract_receiver_type(&method_call.receiver)?;
                let method_name = method_call.method.to_string();
                self.method_return_types
                    .get(&(receiver_type, method_name))
                    .cloned()
            }

            _ => None,
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
    // Currently, the branch profile supports the following SYN create AST expression
    // ExprIf ExprMatch ExprLoop ExprWhile ExprForLoop
    fn profile_branches(&self, stmts: &[Stmt], file: &str, arg_map: &HashMap<String, String>) -> Vec<BranchProfileEntry> {
        let mut branch_profiles = Vec::new();

        for stmt in stmts {
            match stmt {
                // If statement
                Stmt::Expr(Expr::If(if_expr), _) => {
                    let branch_string = format!(
                        "{}:{}:{}",
                        file,
                        if_expr.if_token.span.start().line,
                        if_expr.if_token.span.start().column
                    );

                    let mut branch_sides = vec![self.extract_branch_side(&if_expr.then_branch, file, arg_map)];

                    if let Some((_, else_expr)) = &if_expr.else_branch {
                        if let Expr::Block(block_expr) = &**else_expr {
                            branch_sides.push(self.extract_branch_side(&block_expr.block, file, arg_map));
                        }
                    }

                    branch_profiles.push(BranchProfileEntry {
                        branch_string,
                        branch_sides,
                    });
                }

                // Match statement
                Stmt::Expr(Expr::Match(match_expr), _) => {
                    let branch_string = format!(
                        "{}:{}:{}",
                        file,
                        match_expr.match_token.span.start().line,
                        match_expr.match_token.span.start().column
                    );

                    let mut branch_sides = vec![];
                    for arm in &match_expr.arms {
                        if let Expr::Block(block_expr) = arm.body.as_ref() {
                            branch_sides.push(self.extract_branch_side(&block_expr.block, file, arg_map));
                        }
                    }

                    branch_profiles.push(BranchProfileEntry {
                        branch_string,
                        branch_sides,
                    });
                }

                // While loop
                Stmt::Expr(Expr::While(while_expr), _) => {
                    let branch_string = format!(
                        "{}:{}:{}",
                        file,
                        while_expr.while_token.span.start().line,
                        while_expr.while_token.span.start().column
                    );

                    let branch_side = self.extract_branch_side(&while_expr.body, file, arg_map);

                    branch_profiles.push(BranchProfileEntry {
                        branch_string,
                        branch_sides: vec![branch_side],
                    });
                }

                // For loop
                Stmt::Expr(Expr::ForLoop(for_expr), _) => {
                    let branch_string = format!(
                        "{}:{}:{}",
                        file,
                        for_expr.for_token.span.start().line,
                        for_expr.for_token.span.start().column
                    );

                    let branch_side = self.extract_branch_side(&for_expr.body, file, arg_map);

                    branch_profiles.push(BranchProfileEntry {
                        branch_string,
                        branch_sides: vec![branch_side],
                    });
                }

                // Infinite loop
                Stmt::Expr(Expr::Loop(loop_expr), _) => {
                    let branch_string = format!(
                        "{}:{}:{}",
                        file,
                        loop_expr.loop_token.span.start().line,
                        loop_expr.loop_token.span.start().column
                    );

                    let branch_side = self.extract_branch_side(&loop_expr.body, file, arg_map);

                    branch_profiles.push(BranchProfileEntry {
                        branch_string,
                        branch_sides: vec![branch_side],
                    });
                }

                _ => {}
            }
        }

        branch_profiles
    }

    // Internal helper for retrieving information of the branch side
    fn extract_branch_side(&self, block: &syn::Block, file: &str, arg_map: &HashMap<String, String>) -> BranchSide {
        let mut branch_side_funcs = vec![];
        for stmt in &block.stmts {
            self.extract_called_functions(stmt, &mut branch_side_funcs, &mut vec![], file, arg_map);
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

            for callsite in &mut func.callsites {
                if !callsite.dst.contains("::") {
                    let qualified_name = format!("{}::{}", impl_name, callsite.dst);
                    if function_set.contains(&qualified_name) {
                        callsite.dst = qualified_name;
                    }
                }
            }
            }

            func.function_uses = *self.reverse_call_map.get(&func.name).unwrap_or(&0);
        }
    }

    // Internal helper method to clean function name
    fn clean_function_name(&self, input: String) -> String {
        let mut result = String::new();
        let mut inside_angle_brackets = false;

        for c in input.chars() {
            match c {
                '<' => inside_angle_brackets = true,
                '>' => inside_angle_brackets = false,
                '\'' => continue,
                _ if inside_angle_brackets || c.is_whitespace() => continue,
                _ => result.push(c),
            }
        }


        // Trim unncessary prefix
        let trimmed_result = if result.starts_with("&mut") {
            result[4..].to_string()
        } else if input.starts_with('&') {
            result[1..].to_string()
        } else {
            result
        };

        trimmed_result
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
