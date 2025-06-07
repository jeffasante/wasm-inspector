// tests/integration_test.rs

use wasm_inspector::{analyze_wasm_module, quick_analyze, ExportKind, RiskLevel, ModuleInfo};

// A minimal WASM module for testing (add function that returns 42)
const MINIMAL_WASM: &[u8] = &[
    0x00, 0x61, 0x73, 0x6d, // WASM magic number
    0x01, 0x00, 0x00, 0x00, // Version 1

    // Type section (ID 1)
    0x01, // Section ID
    0x05, // Section size (5 bytes)
    0x01, // Number of types: 1
    0x60, // func_type
    0x00, // params: 0
    0x01, // results: 1
    0x7f, // i32

    // Function section (ID 3)
    0x03, // Section ID
    0x02, // Section size (2 bytes)
    0x01, // Number of functions: 1
    0x00, // Function 0 uses type 0

    // Export section (ID 7)
    0x07, // Section ID
    0x08, // Section size (8 bytes)
    0x01, // Number of exports: 1
    0x04, // Name length: 4 ("main")
    0x6d, 0x61, 0x69, 0x6e, // "main"
    0x00, // Export kind: function
    0x00, // Function index 0

    // Code section (ID 10)
    0x0a, // Section ID
    0x06, // Section size (6 bytes)
    0x01, // Number of function bodies: 1
    // Function body 0:
    0x04, // Body size for function 0: 4 bytes (locals_vec_count + instructions)
    0x00, // Locals vec for function 0: count 0 (0 local decls)
    0x41, // i32.const
    0x2a, // 42
    0x0b, // end
];

// Test with a WASM that has imports (simulated WASI module)
const WASI_WASM: &[u8] = &[
    0x00, 0x61, 0x73, 0x6d, // WASM magic
    0x01, 0x00, 0x00, 0x00, // Version 1

    // Type section (ID 1) - one function type () -> i32
    0x01, // Section ID
    0x05, // Section size (5 bytes)
    0x01, // Number of types: 1
    0x60, // func_type
    0x00, // params: 0
    0x01, // results: 1
    0x7f, // i32

    // Import section (ID 2) - import wasi_snapshot_preview1.fd_read
    0x02, // Section ID
    0x1f, // Section size (31 bytes)
    0x01, // Number of imports: 1
    0x13, // Module name length: 19 ("wasi_snapshot_preview1")
    0x77, 0x61, 0x73, 0x69, 0x5f, 0x73, 0x6e, 0x61, 0x70, 0x73, 0x68, 0x6f, 0x74, 0x5f, 0x70, 0x72, 0x65, 0x76, 0x69, 0x65, 0x77, 0x31, // "wasi_snapshot_preview1"
    0x07, // Import name length: 7 ("fd_read")
    0x66, 0x64, 0x5f, 0x72, 0x65, 0x61, 0x64, // "fd_read"
    0x00, // Import kind: function
    0x00, // Type index for this import: 0

    // Function section (ID 3)
    0x03, // Section ID
    0x02, // Section size (2 bytes)
    0x01, // Number of functions: 1 (this is for locally defined functions)
    0x00, // Function 0 (locally defined) uses type 0

    // Export section (ID 7)
    0x07, // Section ID
    0x0a, // Section size (10 bytes)
    0x01, // Number of exports: 1
    0x06, // Name length: 6 ("_start")
    0x5f, 0x73, 0x74, 0x61, 0x72, 0x74, // "_start"
    0x00, // Export kind: function
    0x01, // Function index to export: 1 (Func 0 is import, Func 1 is 1st defined)

    // Code section (ID 10)
    0x0a, // Section ID
    0x06, // Section size (6 bytes)
    0x01, // Number of function bodies: 1
    // Function body 0:
    0x04, // Body size for function 0 (defined): 4 bytes (locals_vec_count + instructions)
    0x00, // Locals vec for function 0: count 0
    0x41, // i32.const
    0x2a, // 42
    0x0b, // end
];


#[test]
fn test_minimal_wasm_analysis() {
    let analysis_result = analyze_wasm_module(MINIMAL_WASM);
    assert!(analysis_result.is_ok(), "Failed to analyze minimal WASM: {:?}", analysis_result.err());
    let analysis = analysis_result.unwrap();

    // Check basic structure
    assert_eq!(analysis.module_info.version, 1);
    assert_eq!(analysis.module_info.functions.len(), 1, "Incorrect number of defined functions"); // ModuleInfo.functions usually stores defined functions
    assert_eq!(analysis.module_info.exports.len(), 1, "Incorrect number of exports");
    assert_eq!(analysis.module_info.imports.len(), 0, "Incorrect number of imports");

    // Check export
    let export = &analysis.module_info.exports[0];
    assert_eq!(export.name, "main");
    assert!(matches!(export.kind, ExportKind::Function));

    // Check function (assuming ModuleInfo.functions refers to defined functions)
    // The first defined function will have index 0 in the functions vector
    let function = &analysis.module_info.functions[0];
    assert_eq!(function.index, 0, "Function index in defined list mismatch"); // This 'index' is its local index in the defined functions list
    assert!(!function.is_imported);
    assert!(function.is_exported);
    // You might also want to check function.name if your parser populates it from exports/name section
    // assert_eq!(function.name.as_deref(), Some("main"));


    // Check security analysis
    assert!(analysis.security_analysis.capabilities.is_empty(), "Capabilities should be empty for minimal WASM");
    assert!(analysis.security_analysis.vulnerabilities.is_empty(), "Vulnerabilities should be empty for minimal WASM");
    assert!(!analysis.security_analysis.wasi_usage.uses_wasi, "WASI usage should be false for minimal WASM");

    // Check compatibility
    assert!(analysis.compatibility.browser.compatible, "Browser compatibility mismatch");
    assert!(analysis.compatibility.node_js.compatible, "Node.js compatibility mismatch");
    assert!(analysis.compatibility.wasmtime.compatible, "Wasmtime compatibility mismatch");
    assert!(analysis.security_analysis.sandbox_compatibility.browser_safe, "Sandbox browser safety mismatch");
}

#[test]
fn test_quick_analysis() {
    let summary_result = quick_analyze(MINIMAL_WASM);
    assert!(summary_result.is_ok(), "Failed to quick analyze minimal WASM: {:?}", summary_result.err());
    let summary = summary_result.unwrap();
    
    // The function_count in summary might be total (imports + defined)
    // If your ModuleInfo.functions only stores defined, this might differ.
    // For MINIMAL_WASM, imported functions = 0, defined = 1. So total = 1.
    assert_eq!(summary.function_count, 1, "Summary function count mismatch");
    assert_eq!(summary.import_count, 0, "Summary import count mismatch");
    assert_eq!(summary.export_count, 1, "Summary export count mismatch");
    assert!(!summary.has_memory, "Summary memory presence mismatch");
    assert!(!summary.has_start_function, "Summary start function presence mismatch");
    assert!(!summary.uses_wasi, "Summary WASI usage mismatch");
    assert!(matches!(summary.risk_level, RiskLevel::Low), "Summary risk level mismatch");
}

#[test]
fn test_invalid_wasm() {
    let invalid_bytes = &[0x00, 0x00, 0x00, 0x00]; // Not a WASM file
    let result = analyze_wasm_module(invalid_bytes);
    assert!(result.is_err(), "Analysis should fail for invalid WASM bytes");
}

#[test]
fn test_empty_wasm() {
    let empty_bytes = &[];
    let result = analyze_wasm_module(empty_bytes);
    assert!(result.is_err(), "Analysis should fail for empty WASM bytes");
}


#[test]
fn test_wasi_detection() {
    let analysis_result = analyze_wasm_module(WASI_WASM);
    assert!(analysis_result.is_ok(), "Failed to analyze WASI WASM: {:?}", analysis_result.err());
    let analysis = analysis_result.unwrap();
    
    assert_eq!(analysis.module_info.imports.len(), 1, "WASI WASM import count mismatch");
    assert_eq!(analysis.module_info.functions.len(), 1, "WASI WASM defined function count mismatch"); // Number of *defined* functions
    assert_eq!(analysis.module_info.exports.len(), 1, "WASI WASM export count mismatch");

    let import = &analysis.module_info.imports[0];
    assert_eq!(import.module, "wasi_snapshot_preview1");
    assert_eq!(import.name, "fd_read");

    // Should detect WASI usage
    assert!(analysis.security_analysis.wasi_usage.uses_wasi, "WASI usage not detected");
    // Adjust expected version string based on your SecurityAnalyzer's output
    assert_eq!(
        analysis.security_analysis.wasi_usage.wasi_version.as_deref(),
        Some("wasi_snapshot_preview1"), // Or "Preview 1" etc.
        "WASI version mismatch"
    );
    
    let wasi_caps = &analysis.security_analysis.wasi_usage.required_capabilities;
    // Check if *any* capability related to filesystem is present.
    // Your SecurityAnalyzer might produce "filesystem", "file-descriptor-access", etc.
    assert!(
        wasi_caps.iter().any(|cap| cap.contains("file") || cap.contains("filesystem") || cap.contains("fd_")),
        "Required WASI file capabilities not detected. Actual: {:?}", wasi_caps
    );

    // Should detect file system capability in general capabilities
    let has_fs_capability = analysis.security_analysis.capabilities.iter()
        .any(|cap| cap.name == "File System Access");
    assert!(has_fs_capability, "General File System Access capability not detected");

    // Should not be browser compatible due to WASI FS access
    assert!(!analysis.compatibility.browser.compatible, "Browser compatibility should be false");
    assert!(!analysis.security_analysis.sandbox_compatibility.browser_safe, "Sandbox browser safety should be false");

    // Should be compatible with Node.js and Wasmtime (these typically support WASI)
    assert!(analysis.compatibility.node_js.compatible, "Node.js compatibility should be true");
    assert!(analysis.security_analysis.sandbox_compatibility.node_safe, "Sandbox Node.js safety should be true");

    assert!(analysis.compatibility.wasmtime.compatible, "Wasmtime compatibility should be true");
}

 