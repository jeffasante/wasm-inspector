// ===== analyzer.rs =====
// src/analyzer.rs
use crate::graph::CallGraphBuilder;
use crate::security::SecurityAnalyzer;
use crate::types::*;
use crate::memory::{MemoryAnalyzer, MemoryAnalysisResult}; // Added MemoryAnalyzer and Result
use anyhow::Result;


pub struct ModuleAnalyzer<'a> { // Added lifetime 'a
    module_info: ModuleInfo,
    wasm_bytes: &'a [u8], // Added wasm_bytes
}

impl<'a> ModuleAnalyzer<'a> { // Added lifetime 'a
    pub fn new(module_info: ModuleInfo, wasm_bytes: &'a [u8]) -> Self { // Modified signature
        Self { module_info, wasm_bytes }
    }

    pub fn analyze(&mut self) -> Result<ModuleAnalysis> {
        let call_graph = self.build_call_graph()?;
        let security_analysis = self.analyze_security()?;
        let performance_metrics = self.analyze_performance(&call_graph)?; // Pass call_graph
        let compatibility = self.analyze_compatibility()?;
        let memory_analysis = self.analyze_memory_patterns()?; // Added memory analysis call

        Ok(ModuleAnalysis {
            module_info: self.module_info.clone(),
            call_graph,
            security_analysis,
            performance_metrics,
            compatibility,
            memory_analysis, // Added memory_analysis field
        })
    }

    fn build_call_graph(&self) -> Result<CallGraph> {
        // CallGraphBuilder now uses module_info.function_call_instructions,
        // which are populated by WasmParser. No need to pass wasm_bytes to CallGraphBuilder.
        let mut builder = CallGraphBuilder::new(&self.module_info);
        builder.build()
    }

    fn analyze_security(&self) -> Result<SecurityAnalysis> {
        let analyzer = SecurityAnalyzer::new(&self.module_info);
        analyzer.analyze()
    }

    fn analyze_performance(&self, call_graph: &CallGraph) -> Result<PerformanceMetrics> { // Take call_graph
        let module_size = self.calculate_module_size();
        let code_size = self.calculate_code_size();
        let estimated_cold_start_ms = self.estimate_cold_start_time();
        let complexity_score = self.calculate_complexity_score();
        let memory_usage_estimate = self.estimate_memory_usage();
        let optimization_suggestions = self.generate_optimization_suggestions(call_graph); // Pass call_graph

        Ok(PerformanceMetrics {
            module_size,
            code_size,
            estimated_cold_start_ms,
            complexity_score,
            memory_usage_estimate,
            optimization_suggestions,
        })
    }

    fn analyze_compatibility(&self) -> Result<CompatibilityMatrix> {
        let detected_language = self.detect_source_language();

        // Analyze compatibility with different runtimes
        let wasmtime = self.check_wasmtime_compatibility();
        let wasmer = self.check_wasmer_compatibility();
        let browser = self.check_browser_compatibility();
        let node_js = self.check_nodejs_compatibility();
        let deno = self.check_deno_compatibility();
        let cloudflare_workers = self.check_cloudflare_workers_compatibility();

        Ok(CompatibilityMatrix {
            wasmtime,
            wasmer,
            browser,
            node_js,
            deno,
            cloudflare_workers,
            detected_language,
        })
    }

    fn analyze_memory_patterns(&self) -> Result<MemoryAnalysisResult> {
        let mut mem_analyzer = MemoryAnalyzer::new(&self.module_info, self.wasm_bytes);
        mem_analyzer.analyze()
    }


    fn calculate_module_size(&self) -> u32 {
        // Estimate based on sections
        let mut size = 0u32;

        // Function bodies
        size += self
            .module_info
            .functions
            .iter()
            .map(|f| f.body_size)
            .sum::<u32>();

        // Data segments
        size += self
            .module_info
            .data_segments
            .iter()
            .map(|d| d.size)
            .sum::<u32>();

        // Custom sections
        size += self
            .module_info
            .custom_sections
            .iter()
            .map(|c| c.size)
            .sum::<u32>();

        // Add overhead for other sections (type, import, export, etc.)
        size += (self.module_info.imports.len() * 32) as u32; // Rough estimate
        size += (self.module_info.exports.len() * 24) as u32;
        size += (self.module_info.globals.len() * 16) as u32;

        size
    }

    fn calculate_code_size(&self) -> u32 {
        self.module_info
            .functions
            .iter()
            .map(|f| f.body_size)
            .sum::<u32>()
    }

    fn estimate_cold_start_time(&self) -> f64 {
        // Simple heuristic based on module size and complexity
        let base_time = 5.0; // Base 5ms
        let size_factor = (self.calculate_module_size() as f64) / 1024.0 * 0.1; // 0.1ms per KB
        let function_factor = (self.module_info.functions.len() as f64) * 0.01; // 0.01ms per function
        let import_factor = (self.module_info.imports.len() as f64) * 0.05; // 0.05ms per import

        base_time + size_factor + function_factor + import_factor
    }

    fn calculate_complexity_score(&self) -> f64 {
        let mut score = 0.0;

        // Function count contributes to complexity
        score += (self.module_info.functions.len() as f64) * 0.1;

        // Import count (external dependencies)
        score += (self.module_info.imports.len() as f64) * 0.2;

        // Memory usage
        if let Some(ref memory) = self.module_info.memory {
            score += (memory.initial as f64) * 0.001; // 0.001 per page
        }

        // Table usage
        score += (self.module_info.tables.len() as f64) * 0.5;

        // Global variables
        score += (self.module_info.globals.len() as f64) * 0.1;

        // Data segments
        score += (self.module_info.data_segments.len() as f64) * 0.1;

        // Normalize to 0-100 scale
        (score * 10.0).min(100.0)
    }

    fn estimate_memory_usage(&self) -> MemoryUsageEstimate {
        let (initial_memory_kb, max_memory_kb) = if let Some(ref memory) = self.module_info.memory {
            let initial = memory.initial * 64; // WASM pages are 64KB
            let max = memory.maximum.map(|m| m * 64);
            (initial, max)
        } else {
            (0, None)
        };

        // Estimate stack usage based on function complexity
        let stack_estimate = self
            .module_info
            .functions
            .iter()
            .map(|f| {
                // Estimate stack usage per function based on locals
                f.locals
                    .iter()
                    .map(|l| {
                        let type_size = match l.value_type.as_str() {
                            "i32" | "f32" => 4,
                            "i64" | "f64" => 8,
                            _ => 8, // Conservative estimate
                        };
                        l.count * type_size
                    })
                    .sum::<u32>()
            })
            .max()
            .unwrap_or(0)
            / 1024; // Convert to KB

        MemoryUsageEstimate {
            initial_memory_kb,
            max_memory_kb,
            stack_usage_estimate_kb: stack_estimate,
        }
    }

    fn generate_optimization_suggestions(&self, call_graph: &CallGraph) -> Vec<OptimizationSuggestion> {
        let mut suggestions = Vec::new();

        // Check for dead code using the accurate call graph
        if !call_graph.unreachable_functions.is_empty() {
            suggestions.push(OptimizationSuggestion {
                category: "Dead Code".to_string(),
                description: format!(
                    "Found {} unreachable functions (potential dead code)",
                    call_graph.unreachable_functions.len()
                ),
                potential_savings: Some("Varies, can reduce size and improve analysis precision".to_string()),
            });
        }

        // Check memory efficiency
        if let Some(ref memory) = self.module_info.memory {
            if memory.maximum.is_none() {
                suggestions.push(OptimizationSuggestion {
                    category: "Memory".to_string(),
                    description: "Consider setting a maximum memory limit".to_string(),
                    potential_savings: Some("Better resource predictability".to_string()),
                });
            }
        }

        // Check for large data segments
        let large_data_segments = self
            .module_info
            .data_segments
            .iter()
            .filter(|d| d.size > 10_000) // 10KB threshold
            .count();

        if large_data_segments > 0 {
            suggestions.push(OptimizationSuggestion {
                category: "Data".to_string(),
                description: format!(
                    "Found {} large data segments - consider compression",
                    large_data_segments
                ),
                potential_savings: Some("10-30% size reduction".to_string()),
            });
        }

        // Check import efficiency
        let wasi_imports = self
            .module_info
            .imports
            .iter()
            .filter(|i| i.module.starts_with("wasi"))
            .count();

        if wasi_imports > 20 {
            suggestions.push(OptimizationSuggestion {
                category: "Imports".to_string(),
                description: "High number of WASI imports may impact startup time".to_string(),
                potential_savings: Some("Faster cold starts".to_string()),
            });
        }

        suggestions
    }

    fn detect_source_language(&self) -> Option<String> {
        // Analyze patterns to detect source language
        let custom_section_names: std::collections::HashSet<_> = self
            .module_info
            .custom_sections
            .iter()
            .map(|c| c.name.as_str())
            .collect();

        // Rust patterns
        if custom_section_names.contains("name")
            || self
                .module_info
                .imports
                .iter()
                .any(|i| i.module.contains("env") && i.name.contains("__"))
            || self
                .module_info
                .exports
                .iter()
                .any(|e| e.name.contains("__"))
        {
            return Some("Rust".to_string());
        }

        // C/C++ patterns
        if self
            .module_info
            .exports
            .iter()
            .any(|e| e.name == "main" || e.name == "_start")
            || self
                .module_info
                .imports
                .iter()
                .any(|i| i.name.contains("malloc") || i.name.contains("free"))
        {
            return Some("C/C++".to_string());
        }

        // AssemblyScript patterns
        if self
            .module_info
            .exports
            .iter()
            .any(|e| e.name.contains("~lib"))
            || custom_section_names.contains("sourceMappingURL")
        {
            return Some("AssemblyScript".to_string());
        }

        // Go patterns
        if self.module_info.imports.iter().any(|i| i.module == "go") {
            return Some("Go".to_string());
        }

        None
    }

    fn check_wasmtime_compatibility(&self) -> CompatibilityStatus {
        let mut issues = Vec::new();
        let mut required_features = Vec::new();

        // Check for WASI usage
        if self
            .module_info
            .imports
            .iter()
            .any(|i| i.module.starts_with("wasi"))
        {
            required_features.push("WASI support".to_string());
        }

        // Check for multi-memory (not widely supported yet)
        if self.module_info.memory.is_some()
            && self
                .module_info
                .imports
                .iter()
                .any(|i| matches!(i.kind, ImportKind::Memory { .. }))
        {
            issues.push("Multiple memory instances may not be supported".to_string());
        }

        CompatibilityStatus {
            compatible: issues.is_empty(),
            issues,
            required_features,
        }
    }

    fn check_wasmer_compatibility(&self) -> CompatibilityStatus {
        // Similar to wasmtime but with different limitations
        let issues = Vec::new();
        let mut required_features = Vec::new();

        if self
            .module_info
            .imports
            .iter()
            .any(|i| i.module.starts_with("wasi"))
        {
            required_features.push("WASI support".to_string());
        }

        CompatibilityStatus {
            compatible: issues.is_empty(),
            issues,
            required_features,
        }
    }

    fn check_browser_compatibility(&self) -> CompatibilityStatus {
        let mut issues = Vec::new();
        let mut required_features = Vec::new();

        // WASI is not natively supported in browsers
        if self
            .module_info
            .imports
            .iter()
            .any(|i| i.module.starts_with("wasi"))
        {
            issues.push("WASI imports require polyfill in browser".to_string());
            required_features.push("WASI polyfill".to_string());
        }

        // Check for file system access
        if self
            .module_info
            .imports
            .iter()
            .any(|i| i.name.contains("fd_") || i.name.contains("path_") || i.name.contains("file"))
        {
            issues.push("File system access not available in browser sandbox".to_string());
        }

        // Large memory usage might be problematic
        if let Some(ref memory) = self.module_info.memory {
            if memory.initial > 1000 {
                // > ~64MB
                issues.push("Large initial memory allocation may fail in browser".to_string());
            }
        }

        CompatibilityStatus {
            compatible: issues.is_empty(),
            issues,
            required_features,
        }
    }

    fn check_nodejs_compatibility(&self) -> CompatibilityStatus {
        let issues = Vec::new();
        let mut required_features = Vec::new();

        if self
            .module_info
            .imports
            .iter()
            .any(|i| i.module.starts_with("wasi"))
        {
            required_features
                .push("Node.js WASI support (--experimental-wasi-unstable-preview1)".to_string());
        }

        CompatibilityStatus {
            compatible: true, // Node.js has good WASM support
            issues,
            required_features,
        }
    }

    fn check_deno_compatibility(&self) -> CompatibilityStatus {
        let issues = Vec::new();
        let mut required_features = Vec::new();

        if self
            .module_info
            .imports
            .iter()
            .any(|i| i.module.starts_with("wasi"))
        {
            required_features
                .push("Deno WASI support (--allow-read, --allow-write flags)".to_string());
        }

        CompatibilityStatus {
            compatible: true, // Deno has good WASM support
            issues,
            required_features,
        }
    }

    fn check_cloudflare_workers_compatibility(&self) -> CompatibilityStatus {
        let mut issues = Vec::new();
        let required_features = Vec::new();

        // Cloudflare Workers has strict limitations
        if self
            .module_info
            .imports
            .iter()
            .any(|i| i.module.starts_with("wasi"))
        {
            issues.push("WASI not supported in Cloudflare Workers".to_string());
        }

        if let Some(ref memory) = self.module_info.memory {
            if memory.initial > 128 {
                // > ~8MB
                issues.push("Memory limit exceeded for Cloudflare Workers".to_string());
            }
        }

        // Check module size limit (1MB compressed)
        if self.calculate_module_size() > 1_000_000 {
            issues.push("Module may exceed Cloudflare Workers size limit".to_string());
        }

        CompatibilityStatus {
            compatible: issues.is_empty(),
            issues,
            required_features,
        }
    }
}
