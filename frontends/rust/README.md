# Rust frontend

This project provides a tool for analyzing a Rust project directory to extract information about functions and methods, excluding specified directories. It also identifies fuzz_target macros in any fuzzing harness and generates call tree files for these targets. The tool leverages the Syn crate for Abstract Syntax Tree (AST) parsing and provides its functionality through a set of Rust source files.

## How to run
```
cargo run -- $SRC
```

Here’s the expanded **How It Works** section for your `README.md`:

---

## How It Works

This tool operates in three primary phases: 
1. Source analysis and function/method extraction
2. Call tree extraction, generation and output
3. Function data generation and output

The `main.rs` is the major entry points of the Rust frontend analyser. It manage the calls to `analyse.rs`, `call_tree.rs` and `generate_yaml.rs` separately to operates the three phases mentioned above.

### Step 1: Source Analysis and Function/Method Extraction

The `main.rs` takes in a provide source directory path (or retrieved from the environment variable $SRC in OSS-Fuzz docker image). It then pass the project source directory to `analyse.rs` for source analysis and function/method extraction

The `analysis.rs` performs both the source analysis and function/method extraction.

#### Source Analysis
The source analysis process targets to identify all rust source files from the project directory while excluding unnecessary files.

1. **Directory Traversal**: Uses Rust's `std::fs` and `walkdir` crates to traverse the project directory.
2. **File Filtering**: Ensures only `.rs` files are processed.
3. **Exclusion Handling**: Skips files within excluded directories.

#### Function/Method Extraction
The function/method extraction process adopt the **Syn** crate from the rust framework to extract Abstract-Syntax-Tree (AST) of the project source code and extract all functions/methods from the source directory together with their information.

The **Syn** crate provides the following applications:
- **Parsing**: Converts Rust source code into an AST.
- **Traversal**: Provides utilities to traverse the AST and inspect specific nodes.
- **Extraction**: Enables extraction of detailed function and method information, including visibility, attributes, and more.

We integrate the **Syn** crate into our custom **FunctionAnalyser** to traverse functions and methods, extracting essential information for generating function elements, which the Fuzz-Introspector backend processes.

### 1. Parsing Source Files

The tool reads each Rust source file in the target directory, using **Syn**’s `syn::parse_file` to convert the code into an Abstract Syntax Tree (AST). This AST captures the complete structure, including functions, methods, and macros.

### 2. Traversing the AST

`FunctionAnalyser` traverses the AST to identify items of interest: functions (`ItemFn`) and methods (`ImplItemFn`) within implementation blocks (`ItemImpl`). This allows it to capture both standalone functions and associated methods.

### 3. Extracting Function Details

For each function or method, `FunctionAnalyser` extracts key details, including the name (`ident`), signature (parameters and return type), visibility (`Visibility`), and argument information (`FnArg`). These basic details are gathered during traversal.

### 4. Analysing Function Bodies

The tool analyses the function body (`Block`) to calculate cyclomatic complexity and identify function calls from `ExprCall` and `ExprMethodCall` nodes. These calls are stored in a `call_stack` to map functions and their invocations, supporting the generation of `callsites`, `functionUses`, and `functionDepth`.

### 5. Profiling Branches

`FunctionAnalyser` profiles conditional branches, focusing on `if` expressions (`ExprIf`). It builds `BranchProfileEntry` objects that capture branch details, including functions called within each branch. Currently, only `if` expressions are supported.

### 6. Post-Processing

After traversal, the tool calculates function depths by tracing call relationships and resolves fully qualified method names for accuracy. It finalises function use counts from the reverse call map, offering a detailed view of function utilisation.

### Conclusion

By leveraging the **Syn** crate, `FunctionAnalyser` systematically extracts and analyses function and method data, enabling comprehensive code analysis.
