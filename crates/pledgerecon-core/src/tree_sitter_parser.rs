//! Tree-sitter-based source code parsing for reachability analysis.
//!
//! Replaces the regex-based heuristics in `reachability.rs` with proper AST
//! parsing using tree-sitter grammars for Rust, JavaScript, TypeScript,
//! Python, Go, and Java.
//!
//! ## Supported Features
//!
//! - **Import tracking**: static and dynamic imports (require(), import())
//! - **Function definitions**: named functions, arrow functions, methods
//! - **Call expressions**: function calls, method calls, macro calls
//! - **Cross-file resolution**: resolve calls to definitions across files
//! - **Method-level reachability**: track `obj.method()` patterns
//! - **Macro expansion tracking**: Rust macro_rules! invocations

use std::path::Path;
use tracing::debug;
use tree_sitter::{Node, Parser};

/// A parsed import statement.
#[derive(Debug, Clone)]
pub struct ParsedImport {
    /// Module/path being imported from.
    pub module: String,
    /// Local alias or binding name.
    pub alias: String,
    /// Whether this is a dynamic import (require() or import()).
    pub is_dynamic: bool,
}

/// A parsed function definition.
#[derive(Debug, Clone)]
pub struct ParsedFunction {
    /// Function name.
    pub name: String,
    /// Line number (1-indexed).
    pub line: usize,
    /// Functions/methods called within this function body.
    pub calls: Vec<ParsedCall>,
    /// Whether this is an entry point (main, handler, etc.).
    pub is_entry: bool,
}

/// A parsed call expression.
#[derive(Debug, Clone)]
pub struct ParsedCall {
    /// The call target as text (e.g. "foo", "obj.method", "serde::Deserialize").
    pub target: String,
    /// Line number (1-indexed).
    pub line: usize,
    /// Whether this is a method call (contains a `.`).
    pub is_method_call: bool,
    /// Whether this is a macro call (Rust-specific).
    pub is_macro_call: bool,
}

/// The result of parsing a single source file.
#[derive(Debug, Clone, Default)]
pub struct ParsedFile {
    /// All imports found in the file.
    pub imports: Vec<ParsedImport>,
    /// All function definitions found in the file.
    pub functions: Vec<ParsedFunction>,
    /// All calls at the file/module scope (outside any function).
    pub module_calls: Vec<ParsedCall>,
    /// All macro definitions (Rust-specific).
    pub macro_defs: Vec<String>,
    /// Whether this file is an entry point.
    pub is_entry: bool,
}

/// Supported source languages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceLanguage {
    Rust,
    JavaScript,
    TypeScript,
    TypeScriptTsx,
    Python,
    Go,
    Java,
}

impl SourceLanguage {
    /// Detect language from file extension.
    pub fn from_extension(ext: &str) -> Option<Self> {
        match ext {
            "rs" => Some(Self::Rust),
            "js" | "jsx" | "mjs" | "cjs" => Some(Self::JavaScript),
            "ts" => Some(Self::TypeScript),
            "tsx" => Some(Self::TypeScriptTsx),
            "py" => Some(Self::Python),
            "go" => Some(Self::Go),
            "java" => Some(Self::Java),
            _ => None,
        }
    }

    /// Detect language from a file path.
    pub fn from_path(path: &Path) -> Option<Self> {
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        Self::from_extension(ext)
    }
}

/// Parse a source file with tree-sitter and extract structured information.
pub fn parse_source(content: &str, path: &Path) -> Option<ParsedFile> {
    let lang = SourceLanguage::from_path(path)?;
    let source_bytes = content.as_bytes();

    let mut parser = Parser::new();
    match lang {
        SourceLanguage::Rust => {
            parser
                .set_language(&tree_sitter_rust::LANGUAGE.into())
                .ok()?;
        }
        SourceLanguage::JavaScript => {
            parser
                .set_language(&tree_sitter_javascript::LANGUAGE.into())
                .ok()?;
        }
        SourceLanguage::TypeScript => {
            parser
                .set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
                .ok()?;
        }
        SourceLanguage::TypeScriptTsx => {
            parser
                .set_language(&tree_sitter_typescript::LANGUAGE_TSX.into())
                .ok()?;
        }
        SourceLanguage::Python => {
            parser
                .set_language(&tree_sitter_python::LANGUAGE.into())
                .ok()?;
        }
        SourceLanguage::Go => {
            parser.set_language(&tree_sitter_go::LANGUAGE.into()).ok()?;
        }
        SourceLanguage::Java => {
            parser
                .set_language(&tree_sitter_java::LANGUAGE.into())
                .ok()?;
        }
    }

    let tree = parser.parse(content, None)?;
    let root = tree.root_node();

    if root.has_error() {
        debug!("Parse errors in {}", path.display());
    }

    let filename = path
        .file_stem()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown");

    let is_entry = is_entry_point(filename, content, lang);

    let result = match lang {
        SourceLanguage::Rust => parse_rust(&root, source_bytes, is_entry),
        SourceLanguage::JavaScript | SourceLanguage::TypeScript | SourceLanguage::TypeScriptTsx => {
            parse_js_ts(&root, source_bytes, is_entry, lang)
        }
        SourceLanguage::Python => parse_python(&root, source_bytes, is_entry),
        SourceLanguage::Go => parse_go(&root, source_bytes, is_entry),
        SourceLanguage::Java => parse_java(&root, source_bytes, is_entry),
    };

    Some(result)
}

/// Check if a file is likely an entry point.
fn is_entry_point(filename: &str, content: &str, lang: SourceLanguage) -> bool {
    if matches!(
        filename,
        "main" | "index" | "app" | "server" | "mod" | "lib"
    ) {
        return true;
    }
    match lang {
        SourceLanguage::Rust => content.contains("fn main()"),
        SourceLanguage::JavaScript | SourceLanguage::TypeScript | SourceLanguage::TypeScriptTsx => {
            content.contains("export default")
                || content.contains("module.exports")
                || content.contains("if (require.main === module)")
        }
        SourceLanguage::Python => content.contains("if __name__ =="),
        SourceLanguage::Go => content.contains("func main()"),
        SourceLanguage::Java => content.contains("public static void main"),
    }
}

// ─── Rust parser ──────────────────────────────────────────────────────────

fn parse_rust(root: &Node, source: &[u8], is_entry: bool) -> ParsedFile {
    let mut imports = Vec::new();
    let mut functions = Vec::new();
    let mut module_calls = Vec::new();
    let mut macro_defs = Vec::new();

    let mut cursor = root.walk();

    // Walk top-level items.
    for i in 0..root.named_child_count() {
        cursor.reset(*root);
        cursor.goto_first_child();
        for _ in 0..i {
            if !cursor.goto_next_sibling() {
                break;
            }
        }
        let node = cursor.node();

        match node.kind() {
            "use_declaration" => {
                if let Ok(text) = node.utf8_text(source) {
                    let text = text.trim();
                    if let Some(rest) = text.strip_prefix("use ") {
                        let path = rest.trim_end_matches(';');
                        // Handle grouped imports: use std::sync::{Arc, Mutex}
                        if let Some(start) = path.find("::{") {
                            let module = &path[..start];
                            let group = &path[start + 3..].trim_end_matches('}');
                            for item in group.split(',') {
                                let item = item.trim();
                                if !item.is_empty() {
                                    imports.push(ParsedImport {
                                        module: module.to_string(),
                                        alias: item.to_string(),
                                        is_dynamic: false,
                                    });
                                }
                            }
                        } else {
                            let parts: Vec<&str> = path.split("::").collect();
                            if parts.len() >= 2 {
                                let module = parts[..parts.len() - 1].join("::");
                                let alias = parts[parts.len() - 1].trim();
                                imports.push(ParsedImport {
                                    module,
                                    alias: alias.to_string(),
                                    is_dynamic: false,
                                });
                            }
                        }
                    }
                }
            }
            "function_item" | "function_signature_item" => {
                if let Some(func) = parse_rust_function(&node, source) {
                    functions.push(func);
                }
            }
            "macro_definition" => {
                // macro_rules! name { ... }
                if let Some(name_node) = node.child_by_field_name("name")
                    && let Ok(name) = name_node.utf8_text(source)
                {
                    macro_defs.push(name.to_string());
                }
            }
            "macro_invocation" => {
                // Top-level macro call: println!(...), vec![...], etc.
                if let Some(call) = parse_rust_macro_call(&node, source) {
                    module_calls.push(call);
                }
            }
            _ => {}
        }
    }

    // Also collect all calls at module level (not inside functions).
    collect_rust_calls(root, source, &mut module_calls);

    ParsedFile {
        imports,
        functions,
        module_calls,
        macro_defs,
        is_entry,
    }
}

fn parse_rust_function(node: &Node, source: &[u8]) -> Option<ParsedFunction> {
    let name_node = node.child_by_field_name("name")?;
    let name = name_node.utf8_text(source).ok()?.to_string();
    let line = node.start_position().row + 1;

    let is_entry = name == "main";

    // Collect calls within the function body.
    let mut calls = Vec::new();
    let mut cursor = node.walk();
    cursor.goto_first_child();
    loop {
        let child = cursor.node();
        if child.kind() == "call_expression" {
            if let Some(call) = parse_rust_call_expr(&child, source) {
                calls.push(call);
            }
        } else if child.kind() == "macro_invocation"
            && let Some(call) = parse_rust_macro_call(&child, source)
        {
            calls.push(call);
        }
        // Recurse into child nodes to find nested calls.
        collect_rust_calls_in_node(&child, source, &mut calls);

        if !cursor.goto_next_sibling() {
            break;
        }
    }

    Some(ParsedFunction {
        name,
        line,
        calls,
        is_entry,
    })
}

fn parse_rust_call_expr(node: &Node, source: &[u8]) -> Option<ParsedCall> {
    // call_expression: function [arguments]
    let func = node.child_by_field_name("function")?;
    let target = func.utf8_text(source).ok()?.trim().to_string();
    let line = node.start_position().row + 1;
    let is_method_call = target.contains("::") || target.contains('.');

    Some(ParsedCall {
        target,
        line,
        is_method_call,
        is_macro_call: false,
    })
}

fn parse_rust_macro_call(node: &Node, source: &[u8]) -> Option<ParsedCall> {
    // macro_invocation: macro [token_tree]
    let macro_node = node.child_by_field_name("macro")?;
    let target = macro_node.utf8_text(source).ok()?.trim().to_string();
    let line = node.start_position().row + 1;

    Some(ParsedCall {
        target,
        line,
        is_method_call: false,
        is_macro_call: true,
    })
}

fn collect_rust_calls(node: &Node, source: &[u8], calls: &mut Vec<ParsedCall>) {
    let mut cursor = node.walk();
    if cursor.goto_first_child() {
        loop {
            let child = cursor.node();
            if child.kind() == "call_expression" {
                if let Some(call) = parse_rust_call_expr(&child, source) {
                    calls.push(call);
                }
            } else if child.kind() == "macro_invocation"
                && let Some(call) = parse_rust_macro_call(&child, source)
            {
                calls.push(call);
            }
            // Don't recurse into function_item — those are handled separately.
            if child.kind() != "function_item" && child.kind() != "function_signature_item" {
                collect_rust_calls(&child, source, calls);
            }
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
}

fn collect_rust_calls_in_node(node: &Node, source: &[u8], calls: &mut Vec<ParsedCall>) {
    let mut cursor = node.walk();
    if cursor.goto_first_child() {
        loop {
            let child = cursor.node();
            if child.kind() == "call_expression" {
                if let Some(call) = parse_rust_call_expr(&child, source) {
                    calls.push(call);
                }
            } else if child.kind() == "macro_invocation"
                && let Some(call) = parse_rust_macro_call(&child, source)
            {
                calls.push(call);
            }
            collect_rust_calls_in_node(&child, source, calls);
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
}

// ─── JavaScript/TypeScript parser ─────────────────────────────────────────

fn parse_js_ts(root: &Node, source: &[u8], is_entry: bool, lang: SourceLanguage) -> ParsedFile {
    let mut imports = Vec::new();
    let mut functions = Vec::new();
    let mut module_calls = Vec::new();

    // Collect imports and functions by walking the AST.
    walk_js_node(
        root,
        source,
        &mut imports,
        &mut functions,
        &mut module_calls,
        lang,
    );

    ParsedFile {
        imports,
        functions,
        module_calls,
        macro_defs: Vec::new(),
        is_entry,
    }
}

/// Check if a call_expression is a dynamic import: import('module')
fn try_parse_js_dynamic_import(
    node: &Node,
    source: &[u8],
    imports: &mut Vec<ParsedImport>,
) -> bool {
    // The function in a call_expression could be an `import` keyword node,
    // which may not be accessible via child_by_field_name("function").
    let mut is_import_call = false;

    // First try field name.
    if let Some(func) = node.child_by_field_name("function")
        && let Ok(text) = func.utf8_text(source)
        && text.trim() == "import"
    {
        is_import_call = true;
    }

    // Also check children directly for the `import` keyword node.
    if !is_import_call {
        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            loop {
                let child = cursor.node();
                if child.kind() == "import" {
                    is_import_call = true;
                    break;
                }
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }
    }

    if is_import_call {
        let args = node.child_by_field_name("arguments");
        if let Some(args) = args {
            // Walk children of arguments to find the string argument,
            // skipping parens and other anonymous nodes.
            let mut cursor = args.walk();
            if cursor.goto_first_child() {
                loop {
                    let arg = cursor.node();
                    if (arg.kind() == "string" || arg.kind() == "string_fragment")
                        && let Ok(module) = arg.utf8_text(source)
                    {
                        let module = module.trim_matches('\'').trim_matches('"').to_string();
                        imports.push(ParsedImport {
                            module: module.clone(),
                            alias: module,
                            is_dynamic: true,
                        });
                        return true;
                    }
                    if !cursor.goto_next_sibling() {
                        break;
                    }
                }
            }
        }
    }
    false
}

fn walk_js_node(
    node: &Node,
    source: &[u8],
    imports: &mut Vec<ParsedImport>,
    functions: &mut Vec<ParsedFunction>,
    calls: &mut Vec<ParsedCall>,
    lang: SourceLanguage,
) {
    let mut cursor = node.walk();
    if cursor.goto_first_child() {
        loop {
            let child = cursor.node();
            match child.kind() {
                "import_statement" => {
                    parse_js_import(&child, source, imports);
                }
                "function_declaration" | "generator_function_declaration" => {
                    if let Some(func) = parse_js_function(&child, source, lang) {
                        functions.push(func);
                    }
                    // Also scan function body for dynamic imports.
                    collect_js_dynamic_imports(&child, source, imports);
                }
                "export_statement" => {
                    // Handle: export function foo() {}, export default function() {}
                    let mut sub = child.walk();
                    if sub.goto_first_child() {
                        loop {
                            let sub_node = sub.node();
                            if sub_node.kind() == "function_declaration"
                                || sub_node.kind() == "generator_function_declaration"
                            {
                                if let Some(func) = parse_js_function(&sub_node, source, lang) {
                                    functions.push(func);
                                }
                                collect_js_dynamic_imports(&sub_node, source, imports);
                            }
                            if sub_node.kind() == "export_clause" {
                                // export { foo, bar } from 'module'
                                parse_js_export_from(&sub_node, source, imports);
                            }
                            if !sub.goto_next_sibling() {
                                break;
                            }
                        }
                    }
                }
                "lexical_declaration" | "variable_declaration" => {
                    // const foo = () => { ... }
                    // const foo = function() { ... }
                    // const foo = require('bar')
                    parse_js_variable(&child, source, imports, functions, calls, lang);
                }
                "expression_statement" => {
                    // Top-level call: foo() or obj.method()
                    parse_js_expression_statement(&child, source, calls);
                }
                "call_expression" => {
                    // Check for dynamic import: import('module')
                    if !try_parse_js_dynamic_import(&child, source, imports)
                        && let Some(call) = parse_js_call(&child, source)
                    {
                        calls.push(call);
                    }
                    // Recurse for nested calls.
                    walk_js_node(&child, source, imports, functions, calls, lang);
                }
                // Dynamic import: import('module') — may also appear as import_expression
                "import_expression" => {
                    if let Some(module) = child.child_by_field_name("source")
                        && let Ok(module_name) = module.utf8_text(source)
                    {
                        let module_name =
                            module_name.trim_matches('\'').trim_matches('"').to_string();
                        imports.push(ParsedImport {
                            module: module_name.clone(),
                            alias: module_name,
                            is_dynamic: true,
                        });
                    }
                }
                _ => {
                    // Recurse into other nodes.
                    walk_js_node(&child, source, imports, functions, calls, lang);
                }
            }
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
}

/// Recursively scan a node tree for dynamic import() calls.
fn collect_js_dynamic_imports(node: &Node, source: &[u8], imports: &mut Vec<ParsedImport>) {
    let mut cursor = node.walk();
    if cursor.goto_first_child() {
        loop {
            let child = cursor.node();
            if child.kind() == "call_expression" {
                try_parse_js_dynamic_import(&child, source, imports);
            }
            if child.kind() == "import_expression"
                && let Some(module) = child.child_by_field_name("source")
                && let Ok(module_name) = module.utf8_text(source)
            {
                let module_name = module_name.trim_matches('\'').trim_matches('"').to_string();
                imports.push(ParsedImport {
                    module: module_name.clone(),
                    alias: module_name,
                    is_dynamic: true,
                });
            }
            collect_js_dynamic_imports(&child, source, imports);
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
}

fn parse_js_import(node: &Node, source: &[u8], imports: &mut Vec<ParsedImport>) {
    // import_statement can be:
    // import x from 'mod'
    // import { a, b } from 'mod'
    // import * as x from 'mod'
    // import 'mod'  (side-effect only)
    let mut module = String::new();
    let mut clauses = Vec::new();

    let mut cursor = node.walk();
    if cursor.goto_first_child() {
        loop {
            let child = cursor.node();
            match child.kind() {
                "import_clause" => {
                    // Named imports, default import, namespace import
                    let mut sub = child.walk();
                    if sub.goto_first_child() {
                        loop {
                            let sub_node = sub.node();
                            match sub_node.kind() {
                                "identifier" => {
                                    // Default import
                                    if let Ok(name) = sub_node.utf8_text(source) {
                                        clauses.push(name.to_string());
                                    }
                                }
                                "named_imports" => {
                                    let mut ni = sub_node.walk();
                                    if ni.goto_first_child() {
                                        loop {
                                            let ni_node = ni.node();
                                            if ni_node.kind() == "import_specifier"
                                                && let Some(name_node) =
                                                    ni_node.child_by_field_name("name")
                                                && let Ok(name) = name_node.utf8_text(source)
                                            {
                                                clauses.push(name.to_string());
                                            }
                                            if !ni.goto_next_sibling() {
                                                break;
                                            }
                                        }
                                    }
                                }
                                "namespace_import" => {
                                    // import * as x
                                    if let Ok(parent) = child.utf8_text(source) {
                                        // Extract the alias after "as"
                                        if let Some(alias) = parent.split(" as ").nth(1) {
                                            clauses.push(alias.trim().to_string());
                                        }
                                    }
                                }
                                _ => {}
                            }
                            if !sub.goto_next_sibling() {
                                break;
                            }
                        }
                    }
                }
                "string" | "string_fragment" => {
                    if let Ok(text) = child.utf8_text(source) {
                        module = text.trim_matches('\'').trim_matches('"').to_string();
                    }
                }
                _ => {}
            }
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }

    if module.is_empty() {
        return;
    }

    if clauses.is_empty() {
        // Side-effect import: import 'mod'
        imports.push(ParsedImport {
            module: module.clone(),
            alias: module,
            is_dynamic: false,
        });
    } else {
        for clause in clauses {
            imports.push(ParsedImport {
                module: module.clone(),
                alias: clause,
                is_dynamic: false,
            });
        }
    }
}

fn parse_js_export_from(node: &Node, source: &[u8], imports: &mut Vec<ParsedImport>) {
    // export { foo } from 'module'
    let mut cursor = node.walk();
    if cursor.goto_first_child() {
        loop {
            let child = cursor.node();
            if (child.kind() == "string" || child.kind() == "string_fragment")
                && let Ok(text) = child.utf8_text(source)
            {
                let module = text.trim_matches('\'').trim_matches('"').to_string();
                imports.push(ParsedImport {
                    module: module.clone(),
                    alias: module,
                    is_dynamic: false,
                });
            }
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
}

fn parse_js_function(node: &Node, source: &[u8], _lang: SourceLanguage) -> Option<ParsedFunction> {
    let name_node = node.child_by_field_name("name")?;
    let name = name_node.utf8_text(source).ok()?.to_string();
    let line = node.start_position().row + 1;

    let mut calls = Vec::new();
    let body = node.child_by_field_name("body");
    if let Some(body) = body {
        collect_js_calls(&body, source, &mut calls);
    }

    Some(ParsedFunction {
        name,
        line,
        calls,
        is_entry: false,
    })
}

fn parse_js_variable(
    node: &Node,
    source: &[u8],
    imports: &mut Vec<ParsedImport>,
    functions: &mut Vec<ParsedFunction>,
    _calls: &mut Vec<ParsedCall>,
    _lang: SourceLanguage,
) {
    // const x = require('mod')  →  import
    // const x = () => { ... }   →  function
    // const x = function() { ... }  →  function
    // const x = await import('mod')  →  dynamic import

    let mut cursor = node.walk();
    if cursor.goto_first_child() {
        loop {
            let child = cursor.node();
            if child.kind() == "variable_declarator" {
                let name_node = child.child_by_field_name("name");
                let value_node = child.child_by_field_name("value");

                if let (Some(name_node), Some(value_node)) = (name_node, value_node) {
                    let name = name_node.utf8_text(source).ok().unwrap_or("").to_string();

                    // Check for require('module')
                    if value_node.kind() == "call_expression" {
                        let func = value_node.child_by_field_name("function");
                        if let Some(func) = func
                            && let Ok(func_text) = func.utf8_text(source)
                            && func_text.trim() == "require"
                        {
                            // require('module')
                            let args = value_node.child_by_field_name("arguments");
                            if let Some(args) = args {
                                let mut arg_cursor = args.walk();
                                if arg_cursor.goto_first_child() {
                                    let arg = arg_cursor.node();
                                    if let Ok(module) = arg.utf8_text(source) {
                                        let module =
                                            module.trim_matches('\'').trim_matches('"').to_string();
                                        imports.push(ParsedImport {
                                            module: module.clone(),
                                            alias: name.clone(),
                                            is_dynamic: true,
                                        });
                                    }
                                }
                            }
                        }
                    }

                    // Check for await import('module') — dynamic import
                    if value_node.kind() == "await_expression" {
                        // await_expression children: await, call_expression
                        let mut sub = value_node.walk();
                        if sub.goto_first_child() {
                            loop {
                                let sub_node = sub.node();
                                if sub_node.kind() == "call_expression" {
                                    try_parse_js_dynamic_import(&sub_node, source, imports);
                                }
                                if !sub.goto_next_sibling() {
                                    break;
                                }
                            }
                        }
                    }

                    // Check for arrow function or function expression
                    if value_node.kind() == "arrow_function"
                        || value_node.kind() == "function_expression"
                    {
                        let line = node.start_position().row + 1;
                        let mut func_calls = Vec::new();
                        let body = value_node.child_by_field_name("body");
                        if let Some(body) = body {
                            collect_js_calls(&body, source, &mut func_calls);
                        }
                        functions.push(ParsedFunction {
                            name,
                            line,
                            calls: func_calls,
                            is_entry: false,
                        });
                    }
                }
            }
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
}

fn parse_js_expression_statement(node: &Node, source: &[u8], calls: &mut Vec<ParsedCall>) {
    let mut cursor = node.walk();
    if cursor.goto_first_child() {
        let child = cursor.node();
        if child.kind() == "call_expression"
            && let Some(call) = parse_js_call(&child, source)
        {
            calls.push(call);
        }
    }
}

fn parse_js_call(node: &Node, source: &[u8]) -> Option<ParsedCall> {
    let func = node.child_by_field_name("function")?;
    let target = func.utf8_text(source).ok()?.trim().to_string();
    let line = node.start_position().row + 1;
    let is_method_call = target.contains('.');

    Some(ParsedCall {
        target,
        line,
        is_method_call,
        is_macro_call: false,
    })
}

fn collect_js_calls(node: &Node, source: &[u8], calls: &mut Vec<ParsedCall>) {
    let mut cursor = node.walk();
    if cursor.goto_first_child() {
        loop {
            let child = cursor.node();
            if child.kind() == "call_expression" {
                if let Some(call) = parse_js_call(&child, source) {
                    calls.push(call);
                }
                // Also recurse into call arguments.
                collect_js_calls(&child, source, calls);
            } else if child.kind() == "import_expression" {
                // Dynamic import() — record as a call to "import"
                let line = child.start_position().row + 1;
                calls.push(ParsedCall {
                    target: "import".to_string(),
                    line,
                    is_method_call: false,
                    is_macro_call: false,
                });
            } else {
                collect_js_calls(&child, source, calls);
            }
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
}

// ─── Python parser ────────────────────────────────────────────────────────

fn parse_python(root: &Node, source: &[u8], is_entry: bool) -> ParsedFile {
    let mut imports = Vec::new();
    let mut functions = Vec::new();
    let mut module_calls = Vec::new();

    let mut cursor = root.walk();
    if cursor.goto_first_child() {
        loop {
            let child = cursor.node();
            match child.kind() {
                "import_statement" => {
                    // import module  /  import module as alias
                    let mut sub = child.walk();
                    if sub.goto_first_child() {
                        loop {
                            let sub_node = sub.node();
                            if sub_node.kind() == "dotted_name"
                                && let Ok(text) = sub_node.utf8_text(source)
                            {
                                let alias = text.rsplit('.').next().unwrap_or(text).to_string();
                                imports.push(ParsedImport {
                                    module: text.to_string(),
                                    alias,
                                    is_dynamic: false,
                                });
                            }
                            if sub_node.kind() == "aliased_import" {
                                // import x as y
                                let mut ai = sub_node.walk();
                                if ai.goto_first_child() {
                                    let name_node = ai.node();
                                    if let Ok(name) = name_node.utf8_text(source)
                                        && ai.goto_next_sibling()
                                    {
                                        let alias_node = ai.node();
                                        if let Ok(alias) = alias_node.utf8_text(source) {
                                            imports.push(ParsedImport {
                                                module: name.to_string(),
                                                alias: alias.to_string(),
                                                is_dynamic: false,
                                            });
                                        }
                                    }
                                }
                            }
                            if !sub.goto_next_sibling() {
                                break;
                            }
                        }
                    }
                }
                "import_from_statement" => {
                    // from module import func1, func2
                    let module_node = child.child_by_field_name("module_name");
                    let module = module_node
                        .and_then(|n| n.utf8_text(source).ok())
                        .unwrap_or("")
                        .to_string();

                    let mut sub = child.walk();
                    if sub.goto_first_child() {
                        loop {
                            let sub_node = sub.node();
                            if sub_node.kind() == "dotted_name"
                                && sub_node != module_node.unwrap()
                                && let Ok(name) = sub_node.utf8_text(source)
                            {
                                imports.push(ParsedImport {
                                    module: module.clone(),
                                    alias: name.to_string(),
                                    is_dynamic: false,
                                });
                            }
                            if !sub.goto_next_sibling() {
                                break;
                            }
                        }
                    }
                }
                "function_definition" => {
                    if let Some(func) = parse_python_function(&child, source) {
                        functions.push(func);
                    }
                }
                "call" => {
                    if let Some(call) = parse_python_call(&child, source) {
                        module_calls.push(call);
                    }
                }
                _ => {
                    // Recurse for nested structures.
                    collect_python_calls(&child, source, &mut module_calls);
                }
            }
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }

    ParsedFile {
        imports,
        functions,
        module_calls,
        macro_defs: Vec::new(),
        is_entry,
    }
}

fn parse_python_function(node: &Node, source: &[u8]) -> Option<ParsedFunction> {
    let name_node = node.child_by_field_name("name")?;
    let name = name_node.utf8_text(source).ok()?.to_string();
    let line = node.start_position().row + 1;

    let mut calls = Vec::new();
    let mut cursor = node.walk();
    if cursor.goto_first_child() {
        loop {
            let child = cursor.node();
            if child.kind() == "block" {
                collect_python_calls(&child, source, &mut calls);
            }
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }

    Some(ParsedFunction {
        name: name.clone(),
        line,
        calls,
        is_entry: name == "main",
    })
}

fn parse_python_call(node: &Node, source: &[u8]) -> Option<ParsedCall> {
    let func = node.child_by_field_name("function")?;
    let target = func.utf8_text(source).ok()?.trim().to_string();
    let line = node.start_position().row + 1;
    let is_method_call = target.contains('.');

    Some(ParsedCall {
        target,
        line,
        is_method_call,
        is_macro_call: false,
    })
}

fn collect_python_calls(node: &Node, source: &[u8], calls: &mut Vec<ParsedCall>) {
    let mut cursor = node.walk();
    if cursor.goto_first_child() {
        loop {
            let child = cursor.node();
            if child.kind() == "call" {
                if let Some(call) = parse_python_call(&child, source) {
                    calls.push(call);
                }
                collect_python_calls(&child, source, calls);
            } else if child.kind() != "function_definition" {
                collect_python_calls(&child, source, calls);
            }
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
}

// ─── Go parser ────────────────────────────────────────────────────────────

fn parse_go(root: &Node, source: &[u8], is_entry: bool) -> ParsedFile {
    let mut imports = Vec::new();
    let mut functions = Vec::new();
    let mut module_calls = Vec::new();

    let mut cursor = root.walk();
    if cursor.goto_first_child() {
        loop {
            let child = cursor.node();
            match child.kind() {
                "import_declaration" => {
                    // import "module"  /  import ( "mod1" \n "mod2" )
                    parse_go_imports(&child, source, &mut imports);
                }
                "function_declaration" => {
                    if let Some(func) = parse_go_function(&child, source) {
                        functions.push(func);
                    }
                }
                "call_expression" => {
                    if let Some(call) = parse_go_call(&child, source) {
                        module_calls.push(call);
                    }
                }
                _ => {
                    collect_go_calls(&child, source, &mut module_calls);
                }
            }
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }

    ParsedFile {
        imports,
        functions,
        module_calls,
        macro_defs: Vec::new(),
        is_entry,
    }
}

fn parse_go_imports(node: &Node, source: &[u8], imports: &mut Vec<ParsedImport>) {
    // import_declaration contains either import_spec directly (single import)
    // or import_spec_list (parenthesized multiple imports).
    let mut cursor = node.walk();
    if cursor.goto_first_child() {
        loop {
            let child = cursor.node();
            if child.kind() == "import_spec" {
                parse_go_import_spec(&child, source, imports);
            } else if child.kind() == "import_spec_list" {
                // Recurse into import_spec_list to find individual import_spec nodes.
                let mut sub = child.walk();
                if sub.goto_first_child() {
                    loop {
                        let sub_node = sub.node();
                        if sub_node.kind() == "import_spec" {
                            parse_go_import_spec(&sub_node, source, imports);
                        }
                        if !sub.goto_next_sibling() {
                            break;
                        }
                    }
                }
            }
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
}

fn parse_go_import_spec(node: &Node, source: &[u8], imports: &mut Vec<ParsedImport>) {
    let mut cursor = node.walk();
    if cursor.goto_first_child() {
        loop {
            let child = cursor.node();
            if child.kind() == "interpreted_string_literal"
                && let Ok(text) = child.utf8_text(source)
            {
                let module = text.trim_matches('"').trim_matches('`').to_string();
                let alias = module.rsplit('/').next().unwrap_or(&module).to_string();
                imports.push(ParsedImport {
                    module,
                    alias,
                    is_dynamic: false,
                });
            }
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
}

fn parse_go_function(node: &Node, source: &[u8]) -> Option<ParsedFunction> {
    let name_node = node.child_by_field_name("name")?;
    let name = name_node.utf8_text(source).ok()?.to_string();
    let line = node.start_position().row + 1;

    let mut calls = Vec::new();
    let body = node.child_by_field_name("body");
    if let Some(body) = body {
        collect_go_calls(&body, source, &mut calls);
    }

    Some(ParsedFunction {
        name: name.clone(),
        line,
        calls,
        is_entry: name == "main",
    })
}

fn parse_go_call(node: &Node, source: &[u8]) -> Option<ParsedCall> {
    let func = node.child_by_field_name("function")?;
    let target = func.utf8_text(source).ok()?.trim().to_string();
    let line = node.start_position().row + 1;
    let is_method_call = target.contains('.');

    Some(ParsedCall {
        target,
        line,
        is_method_call,
        is_macro_call: false,
    })
}

fn collect_go_calls(node: &Node, source: &[u8], calls: &mut Vec<ParsedCall>) {
    let mut cursor = node.walk();
    if cursor.goto_first_child() {
        loop {
            let child = cursor.node();
            if child.kind() == "call_expression" {
                if let Some(call) = parse_go_call(&child, source) {
                    calls.push(call);
                }
                collect_go_calls(&child, source, calls);
            } else if child.kind() != "function_declaration" {
                collect_go_calls(&child, source, calls);
            }
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
}

// ─── Java parser ──────────────────────────────────────────────────────────

fn parse_java(root: &Node, source: &[u8], is_entry: bool) -> ParsedFile {
    let mut imports = Vec::new();
    let mut functions = Vec::new();
    let mut module_calls = Vec::new();

    // Java has methods nested inside class_declaration → class_body.
    // Walk recursively to find all imports, methods, and calls.
    walk_java_node(
        root,
        source,
        &mut imports,
        &mut functions,
        &mut module_calls,
    );

    ParsedFile {
        imports,
        functions,
        module_calls,
        macro_defs: Vec::new(),
        is_entry,
    }
}

fn walk_java_node(
    node: &Node,
    source: &[u8],
    imports: &mut Vec<ParsedImport>,
    functions: &mut Vec<ParsedFunction>,
    calls: &mut Vec<ParsedCall>,
) {
    let mut cursor = node.walk();
    if cursor.goto_first_child() {
        loop {
            let child = cursor.node();
            match child.kind() {
                "import_declaration" => {
                    // import package.Class;
                    if let Ok(text) = child.utf8_text(source) {
                        let text = text.trim();
                        if let Some(rest) = text.strip_prefix("import ") {
                            let path = rest.trim_end_matches(';').trim_end_matches(".*").trim();
                            let parts: Vec<&str> = path.split('.').collect();
                            if parts.len() >= 2 {
                                let module = parts[..parts.len() - 1].join(".");
                                let alias = parts[parts.len() - 1].to_string();
                                imports.push(ParsedImport {
                                    module,
                                    alias,
                                    is_dynamic: false,
                                });
                            }
                        }
                    }
                }
                "method_declaration" => {
                    if let Some(func) = parse_java_method(&child, source) {
                        functions.push(func);
                    }
                    // Also collect calls within the method body.
                    if let Some(body) = child.child_by_field_name("body") {
                        collect_java_calls(&body, source, calls);
                    }
                }
                "method_invocation" => {
                    if let Some(call) = parse_java_call(&child, source) {
                        calls.push(call);
                    }
                }
                _ => {
                    // Recurse into class_declaration, class_body, etc.
                    walk_java_node(&child, source, imports, functions, calls);
                }
            }
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
}

fn parse_java_method(node: &Node, source: &[u8]) -> Option<ParsedFunction> {
    let name_node = node.child_by_field_name("name")?;
    let name = name_node.utf8_text(source).ok()?.to_string();
    let line = node.start_position().row + 1;

    let mut calls = Vec::new();
    let body = node.child_by_field_name("body");
    if let Some(body) = body {
        collect_java_calls(&body, source, &mut calls);
    }

    Some(ParsedFunction {
        name: name.clone(),
        line,
        calls,
        is_entry: name == "main",
    })
}

fn parse_java_call(node: &Node, source: &[u8]) -> Option<ParsedCall> {
    // method_invocation: object . name ( arguments )
    // or just: name ( arguments )
    let name_node = node.child_by_field_name("name")?;
    let name = name_node.utf8_text(source).ok()?.to_string();

    let target = if let Some(obj) = node.child_by_field_name("object") {
        if let Ok(obj_text) = obj.utf8_text(source) {
            format!("{}.{}", obj_text.trim(), name)
        } else {
            name
        }
    } else {
        name
    };

    let line = node.start_position().row + 1;
    let is_method_call = target.contains('.');

    Some(ParsedCall {
        target,
        line,
        is_method_call,
        is_macro_call: false,
    })
}

fn collect_java_calls(node: &Node, source: &[u8], calls: &mut Vec<ParsedCall>) {
    let mut cursor = node.walk();
    if cursor.goto_first_child() {
        loop {
            let child = cursor.node();
            if child.kind() == "method_invocation" {
                if let Some(call) = parse_java_call(&child, source) {
                    calls.push(call);
                }
                collect_java_calls(&child, source, calls);
            } else if child.kind() != "method_declaration" {
                collect_java_calls(&child, source, calls);
            }
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_rust_source() {
        let code = r#"
use std::sync::Arc;
use serde::{Deserialize, Serialize};

fn main() {
    let data = Arc::new(42);
    println!("hello");
    helper(data);
}

fn helper(x: Arc<i32>) {
    println!("got: {:?}", x);
}

macro_rules! debug_print {
    ($e:expr) => { println!("{:?}", $e) };
}
"#;
        let path = Path::new("test.rs");
        let result = parse_source(code, path).unwrap();

        assert!(result.imports.iter().any(|i| i.alias == "Arc"));
        assert!(result.imports.iter().any(|i| i.alias == "Deserialize"));
        assert!(result.imports.iter().any(|i| i.alias == "Serialize"));
        assert!(
            result
                .functions
                .iter()
                .any(|f| f.name == "main" && f.is_entry)
        );
        assert!(result.functions.iter().any(|f| f.name == "helper"));
        assert!(result.macro_defs.contains(&"debug_print".to_string()));
    }

    #[test]
    fn test_parse_javascript_source() {
        let code = r#"
const lodash = require('lodash');
import { readFile } from 'fs';
import express from 'express';

function handler(req, res) {
    const data = readFile('/path');
    lodash.template(data);
    express();
}

const arrow = () => {
    handler(null, null);
};
"#;
        let path = Path::new("test.js");
        let result = parse_source(code, path).unwrap();

        assert!(
            result
                .imports
                .iter()
                .any(|i| i.alias == "lodash" && i.is_dynamic)
        );
        assert!(
            result
                .imports
                .iter()
                .any(|i| i.alias == "readFile" && !i.is_dynamic)
        );
        assert!(
            result
                .imports
                .iter()
                .any(|i| i.alias == "express" && !i.is_dynamic)
        );
        assert!(result.functions.iter().any(|f| f.name == "handler"));
        assert!(result.functions.iter().any(|f| f.name == "arrow"));
    }

    #[test]
    fn test_parse_typescript_source() {
        let code = r#"
import { Component } from 'react';

interface Props {
    name: string;
}

class MyComponent extends Component<Props> {
    render() {
        return this.props.name;
    }
}

export function main(): void {
    const c = new MyComponent();
    c.render();
}
"#;
        let path = Path::new("test.ts");
        let result = parse_source(code, path).unwrap();

        assert!(result.imports.iter().any(|i| i.alias == "Component"));
        assert!(result.functions.iter().any(|f| f.name == "main"));
    }

    #[test]
    fn test_parse_python_source() {
        let code = r#"
import os
from pathlib import Path

def main():
    path = Path('/tmp')
    files = os.listdir(path)
    print(files)

def helper():
    pass
"#;
        let path = Path::new("test.py");
        let result = parse_source(code, path).unwrap();

        assert!(result.imports.iter().any(|i| i.alias == "os"));
        assert!(result.imports.iter().any(|i| i.alias == "Path"));
        assert!(
            result
                .functions
                .iter()
                .any(|f| f.name == "main" && f.is_entry)
        );
        assert!(result.functions.iter().any(|f| f.name == "helper"));
    }

    #[test]
    fn test_parse_go_source() {
        let code = r#"
package main

import (
    "fmt"
    "net/http"
)

func main() {
    fmt.Println("hello")
    http.ListenAndServe(":8080", nil)
}

func handler(w http.ResponseWriter, r *http.Request) {
    fmt.Fprintf(w, "hello")
}
"#;
        let path = Path::new("test.go");
        let result = parse_source(code, path).unwrap();

        assert!(result.imports.iter().any(|i| i.alias == "fmt"));
        assert!(result.imports.iter().any(|i| i.alias == "http"));
        assert!(
            result
                .functions
                .iter()
                .any(|f| f.name == "main" && f.is_entry)
        );
        assert!(result.functions.iter().any(|f| f.name == "handler"));
    }

    #[test]
    fn test_parse_java_source() {
        let code = r#"
import java.util.List;
import java.io.File;

public class Main {
    public static void main(String[] args) {
        List<String> list = new ArrayList<>();
        File file = new File("/tmp");
        file.exists();
    }

    private void process() {
        System.out.println("processing");
    }
}
"#;
        let path = Path::new("Main.java");
        let result = parse_source(code, path).unwrap();

        assert!(result.imports.iter().any(|i| i.alias == "List"));
        assert!(result.imports.iter().any(|i| i.alias == "File"));
        assert!(
            result
                .functions
                .iter()
                .any(|f| f.name == "main" && f.is_entry)
        );
        assert!(result.functions.iter().any(|f| f.name == "process"));
    }

    #[test]
    fn test_dynamic_import_tracking() {
        let code = r#"
async function loadModule() {
    const mod = await import('heavy-module');
    mod.doSomething();
}
"#;
        let path = Path::new("dynamic.js");
        let result = parse_source(code, path).unwrap();

        assert!(
            result
                .imports
                .iter()
                .any(|i| i.is_dynamic && i.module == "heavy-module")
        );
    }

    #[test]
    fn test_method_level_calls() {
        let code = r#"
const _ = require('lodash');

function process(data) {
    const template = _.template(data);
    return template();
}
"#;
        let path = Path::new("method.js");
        let result = parse_source(code, path).unwrap();

        let func = result
            .functions
            .iter()
            .find(|f| f.name == "process")
            .unwrap();
        assert!(
            func.calls
                .iter()
                .any(|c| c.target.contains("template") && c.is_method_call)
        );
    }

    #[test]
    fn test_rust_macro_tracking() {
        let code = r#"
fn main() {
    println!("hello");
    vec![1, 2, 3];
    debug_print!(42);
}

macro_rules! debug_print {
    ($e:expr) => { println!("{:?}", $e) };
}
"#;
        let path = Path::new("macro.rs");
        let result = parse_source(code, path).unwrap();

        assert!(result.macro_defs.contains(&"debug_print".to_string()));
        let main = result.functions.iter().find(|f| f.name == "main").unwrap();
        assert!(
            main.calls
                .iter()
                .any(|c| c.is_macro_call && c.target == "println")
        );
        assert!(
            main.calls
                .iter()
                .any(|c| c.is_macro_call && c.target == "vec")
        );
        assert!(
            main.calls
                .iter()
                .any(|c| c.is_macro_call && c.target == "debug_print")
        );
    }

    #[test]
    fn test_language_detection() {
        assert_eq!(
            SourceLanguage::from_extension("rs"),
            Some(SourceLanguage::Rust)
        );
        assert_eq!(
            SourceLanguage::from_extension("js"),
            Some(SourceLanguage::JavaScript)
        );
        assert_eq!(
            SourceLanguage::from_extension("ts"),
            Some(SourceLanguage::TypeScript)
        );
        assert_eq!(
            SourceLanguage::from_extension("tsx"),
            Some(SourceLanguage::TypeScriptTsx)
        );
        assert_eq!(
            SourceLanguage::from_extension("py"),
            Some(SourceLanguage::Python)
        );
        assert_eq!(
            SourceLanguage::from_extension("go"),
            Some(SourceLanguage::Go)
        );
        assert_eq!(
            SourceLanguage::from_extension("java"),
            Some(SourceLanguage::Java)
        );
        assert_eq!(SourceLanguage::from_extension("unknown"), None);
    }
}
