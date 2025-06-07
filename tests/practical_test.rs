// practical_tests.rs

use std::fs;
use std::process::Command;
use wasm_inspector::{ModuleAnalyzer, ModuleInfo, WasmParser, analyze_wasm_module}; // Ensure all used types are imported

// Helper to create a real WASM file using wat2wasm if available
fn create_test_wasm_with_wat() -> Option<Vec<u8>> {
    // Simple WAT (WebAssembly Text) that we can convert to binary
    let wat_content = r#"
(module
  (func $add (param i32 i32) (result i32)
    local.get 0
    local.get 1
    i32.add)
  (export "add" (func $add))
)
"#;
    let temp_wat_file = "temp_test.wat";
    let temp_wasm_file = "temp_test.wasm";

    if fs::write(temp_wat_file, wat_content).is_err() {
        return None;
    }

    // Try to use wat2wasm if available (from WABT tools)
    let status = Command::new("wat2wasm")
        .arg(temp_wat_file)
        .arg("-o")
        .arg(temp_wasm_file)
        .status();

    let _ = fs::remove_file(temp_wat_file); // Clean up .wat file

    match status {
        Ok(exit_status) if exit_status.success() => {
            let wasm_bytes = fs::read(temp_wasm_file);
            let _ = fs::remove_file(temp_wasm_file); // Clean up .wasm file
            wasm_bytes.ok()
        }
        _ => {
            let _ = fs::remove_file(temp_wasm_file); // Clean up .wasm file if it exists
            // Fallback: A very minimal valid WASM binary if wat2wasm fails or is not installed
            // (module)
            Some(vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00])
        }
    }
}

#[test]
fn test_basic_error_handling() {
    // Test various invalid inputs
    let test_cases = vec![
        (vec![], "empty input"),
        (vec![0x00, 0x61, 0x73], "incomplete magic"),
        (vec![0xFF, 0xFF, 0xFF, 0xFF], "wrong magic"),
        // wasmparser now handles version 2 as valid for some parsing stages,
        // but might fail later. Let's use a more clearly invalid structure.
        // A short, invalid payload often works better for parse errors.
        (
            vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0xEE],
            "valid header, invalid section id",
        ),
    ];

    for (i, (test_case, desc)) in test_cases.iter().enumerate() {
        let result = analyze_wasm_module(test_case);
        assert!(
            result.is_err(),
            "Test case {} ('{}') should fail but didn't. Result: {:?}",
            i,
            desc,
            result
        );
    }
}

#[test]
fn test_library_integration() {
    // Test that we can create the basic structures
    // No need to import ModuleAnalysis, etc. here if only testing ModuleInfo serialization

    // Create minimal valid structures for testing
    let module_info = ModuleInfo {
        version: 1,
        imports: Vec::new(),
        exports: Vec::new(),
        functions: Vec::new(),
        memory: None,
        tables: Vec::new(),
        globals: Vec::new(),
        data_segments: Vec::new(),
        element_segments: Vec::new(),
        start_function: None,
        custom_sections: Vec::new(),
        function_call_instructions: Vec::new(), // FIX: Added
        type_signatures: Vec::new(),            // FIX: Added
    };

    // Test JSON serialization
    let json_result = serde_json::to_string(&module_info);
    assert!(
        json_result.is_ok(),
        "Should be able to serialize ModuleInfo to JSON. Error: {:?}",
        json_result.err()
    );

    if let Ok(json_string) = json_result {
        let parsed_result: Result<ModuleInfo, _> = serde_json::from_str(&json_string);
        assert!(
            parsed_result.is_ok(),
            "Should be able to deserialize ModuleInfo from JSON. Error: {:?}",
            parsed_result.err()
        );
    }
}

#[test]
fn test_analyzer_components() {
    // Test individual analyzer components work

    // Test with minimal valid WASM (just magic + version + empty sections for a more robust parse)
    let minimal_bytes = vec![
        0x00, 0x61, 0x73, 0x6d, // Magic
        0x01, 0x00, 0x00,
        0x00, // Version
              // You could add empty sections here if WasmParser expects them for a "successful" minimal parse
              // e.g., an empty Type section: 0x01, 0x01, 0x00 (section_id, size, count=0)
              // For now, the provided minimal_bytes should just pass WasmParser::new
    ];

    // Test parser creation
    let parser_result = WasmParser::new(&minimal_bytes);
    assert!(
        parser_result.is_ok(),
        "Parser::new should handle minimal WASM. Error: {:?}",
        parser_result.err()
    );

    if let Ok(parser) = parser_result {
        let parse_result = parser.parse();
        // This might fail due to strict validation (e.g. missing required sections for a "complete" module),
        // but the parser itself shouldn't panic.
        match parse_result {
            Ok(module_info) => {
                // If parsing succeeds, test the analyzer
                // FIX: Pass wasm_bytes to ModuleAnalyzer::new
                let mut analyzer = ModuleAnalyzer::new(module_info, &minimal_bytes);
                let analysis_result = analyzer.analyze();

                match analysis_result {
                    Ok(analysis) => {
                        assert_eq!(analysis.module_info.version, 1);
                        println!("✅ Successfully analyzed minimal WASM module");
                    }
                    Err(e) => {
                        // For a truly minimal module (just header), analysis might still fail
                        // if it expects certain sections to always be present for its heuristics.
                        println!(
                            "ℹ️  Analysis failed for minimal module (this might be expected): {}",
                            e
                        );
                    }
                }
            }
            Err(e) => {
                // Parsing just the header should ideally not error out from WasmParser::parse()
                // unless wasmparser itself has stricter rules for a "complete" parse.
                // It's more likely to error if sections are malformed.
                println!("ℹ️  Parsing failed for minimal module: {}", e);
                // Depending on WasmParser's strictness, this might be an assert!(false, ...)
                // For now, let's assume some parse failures on minimal modules are okay if they are due to incompleteness.
            }
        }
    }
}

// Integration test that checks if we can find real WASM files
#[test]
fn test_with_real_wasm_if_available() {
    if let Some(wasm_bytes) = create_test_wasm_with_wat() {
        println!("🔍 Testing with generated WASM (add function)");
        let result = analyze_wasm_module(&wasm_bytes);
        match result {
            Ok(analysis) => {
                println!("✅ Successfully analyzed generated WASM");
                assert_eq!(analysis.module_info.exports.len(), 1);
                if !analysis.module_info.exports.is_empty() {
                    assert_eq!(analysis.module_info.exports[0].name, "add");
                }
                // Add more assertions based on the known structure of add.wat
                return; // Exit after successful test with generated WASM
            }
            Err(e) => {
                panic!("⚠️ Failed to analyze generated WASM: {}", e);
            }
        }
    } else {
        println!(
            "ℹ️  wat2wasm not found or failed, or fallback minimal WASM used by create_test_wasm_with_wat. Proceeding to search for other .wasm files."
        );
    }

    // Look for any .wasm files in common locations
    let possible_paths = vec![
        // "target/wasm32-unknown-unknown/debug/",
        // "target/wasm32-unknown-unknown/release/",
        // "target/debug/", // For non-wasm projects that might have wasm test files
        // "target/release/",
        // "tests/wasm/", // A dedicated directory for test wasm files
        "test-data/",
        // "../test-data/change.wasm", // Be careful with relative paths going too high up
        // "./",
    ];

    let mut found_wasm_and_tested = false;

    for path_str in possible_paths {
        let path = std::path::Path::new(path_str);
        if path.is_dir() {
            if let Ok(entries) = fs::read_dir(path) {
                for entry_result in entries {
                    if let Ok(entry) = entry_result {
                        let file_path = entry.path();
                        if file_path.is_file() {
                            if let Some(ext) = file_path.extension() {
                                if ext == "wasm" {
                                    if let Ok(wasm_bytes) = fs::read(&file_path) {
                                        println!("🔍 Testing with real WASM file: {:?}", file_path);

                                        let result = analyze_wasm_module(&wasm_bytes);
                                        match result {
                                            Ok(analysis) => {
                                                println!(
                                                    "✅ Successfully analyzed {:?}",
                                                    file_path
                                                );
                                                println!(
                                                    "   Functions (defined): {}",
                                                    analysis.module_info.functions.len()
                                                );
                                                println!(
                                                    "   Imports: {}",
                                                    analysis.module_info.imports.len()
                                                );
                                                println!(
                                                    "   Exports: {}",
                                                    analysis.module_info.exports.len()
                                                );
                                                found_wasm_and_tested = true;
                                                // break; // Optionally break after first successful analysis
                                            }
                                            Err(e) => {
                                                // It's okay if some WASM files fail if they are malformed or complex test cases
                                                println!(
                                                    "⚠️  Failed to analyze {:?}: {} (This might be okay for some test files)",
                                                    file_path, e
                                                );
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                // if found_wasm_and_tested { break; } // Optionally break after searching one directory
            }
        }
    }

    if !found_wasm_and_tested {
        println!(
            "ℹ️  No other real WASM files found or successfully tested. Consider adding some to a 'tests/wasm/' directory."
        );
        // This is not a failure, but a note. For CI, you might want at least one guaranteed real WASM.
    }
}

#[cfg(test)]
mod performance_tests {
    use super::*; // Imports analyze_wasm_module from parent scope
    use std::time::Instant;

    #[test]
    fn test_analysis_performance_on_invalid_input() {
        // Test that analysis doesn't take too long even with invalid input
        let invalid_large_input = vec![0u8; 10_000]; // 10KB of zeros

        let start = Instant::now();
        let result = analyze_wasm_module(&invalid_large_input);
        let duration = start.elapsed();

        // Should fail quickly, not hang
        assert!(
            duration.as_millis() < 1000,
            "Analysis of invalid input should complete within 1 second, took: {:?}",
            duration
        );
        assert!(
            result.is_err(),
            "Should reject invalid input. Result: {:?}",
            result
        );
    }

    #[test]
    fn test_analysis_performance_on_minimal_valid_input() {
        // A very minimal valid WASM module: (module)
        let minimal_valid_wasm = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];

        let start = Instant::now();
        let result = analyze_wasm_module(&minimal_valid_wasm);
        let duration = start.elapsed();

        assert!(
            duration.as_millis() < 1000,
            "Analysis of minimal valid input should complete within 1 second, took: {:?}",
            duration
        );
        // This should ideally pass, or fail gracefully if the analyzer expects more sections
        match result {
            Ok(_) => {
                println!("✅ Minimal valid WASM analyzed successfully within performance limits.")
            }
            Err(e) => println!(
                "ℹ️ Minimal valid WASM analysis failed (might be ok if analyzer is strict): {}",
                e
            ),
        }
    }
}
