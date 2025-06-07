
// ===== lib.rs =====
// src/lib.rs
pub mod analyzer;
pub mod types;
pub mod parser;
pub mod graph;
pub mod security;
pub mod memory; // Added memory module

// src/lib.rs

pub use analyzer::*;
pub use types::*;
pub use parser::*;

use anyhow::Result;

use wasm_bindgen::prelude::*;
use serde_json; // For serializing the result to JSON string


/// Main entry point for WASM module analysis
pub fn analyze_wasm_module(bytes: &[u8]) -> Result<ModuleAnalysis>{
    let parser = WasmParser::new(bytes)?;
    let module_info = parser.parse()?;
    
    let mut analyzer = ModuleAnalyzer::new(module_info, bytes); // Pass bytes
    analyzer.analyze()
}

/// Quick summary analysis for CLI/API responses
pub fn quick_analyze(bytes: &[u8]) -> Result<ModuleSummary> {
    let analysis = analyze_wasm_module(bytes)?;
    Ok(ModuleSummary::from(analysis))
}


#[wasm_bindgen]
pub fn analyze_wasm_bytes_for_web(wasm_bytes: &[u8]) -> Result<String, JsValue> {
    // Use a panic hook for better error messages in the browser console
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();

    match crate::analyze_wasm_module(wasm_bytes) {
        Ok(analysis_result) => {
            serde_json::to_string(&analysis_result)
                .map_err(|e| JsValue::from_str(&format!("JSON serialization error: {}", e)))
        }
        Err(e) => Err(JsValue::from_str(&format!("WASM Analysis Error: {}", e))),
    }
}