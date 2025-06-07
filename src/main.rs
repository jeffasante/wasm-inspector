// ===== main.rs =====
// src/main.rs
use clap::{Arg, Command};
use std::fs;
use wasm_inspector::{
    CallGraph, CompatibilityMatrix, ModuleAnalysis, ModuleInfo, PerformanceMetrics, RiskLevel,
    SecurityAnalysis, analyze_wasm_module, memory::MemoryAnalysisResult, quick_analyze,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = Command::new("WASM Inspector")
        .version("0.1.0")
        .author("Your Name")
        .about("Analyze and inspect WebAssembly modules")
        .arg(
            Arg::new("file")
                .help("WASM file to analyze")
                .required(true)
                .index(1),
        )
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .value_name("FILE")
                .help("Output file for analysis results (JSON format)"),
        )
        .arg(
            Arg::new("format")
                .short('f')
                .long("format")
                .value_name("FORMAT")
                .help("Output format: json, summary, detailed")
                .default_value("summary"),
        )
        .arg(
            Arg::new("security")
                .long("security-only")
                .action(clap::ArgAction::SetTrue)
                .help("Show only security analysis"),
        )
        .arg(
            Arg::new("performance")
                .long("performance-only")
                .action(clap::ArgAction::SetTrue)
                .help("Show only performance analysis"),
        )
        .arg(
            Arg::new("compatibility")
                .long("compatibility-only")
                .action(clap::ArgAction::SetTrue)
                .help("Show only compatibility analysis"),
        )
        .get_matches();

    let file_path = matches.get_one::<String>("file").unwrap();
    let format = matches.get_one::<String>("format").unwrap();

    // Read the WASM file
    let bytes =
        fs::read(file_path).map_err(|e| format!("Failed to read file '{}': {}", file_path, e))?;

    // Validate it's a WASM file
    if !bytes.starts_with(&[0x00, 0x61, 0x73, 0x6d]) {
        return Err("File does not appear to be a valid WASM module.".into());
    }

    println!("[INFO] Analyzing WASM module: {}", file_path);
    println!("[INFO] File size: {} bytes", bytes.len());
    println!();

    match format.as_str() {
        "json" => {
            let analysis = analyze_wasm_module(&bytes)?;
            let json = serde_json::to_string_pretty(&analysis)?;

            if let Some(output_file) = matches.get_one::<String>("output") {
                fs::write(output_file, &json)?;
                println!("[OK] Analysis saved to: {}", output_file);
            } else {
                println!("{}", json);
            }
        }
        "summary" => {
            let summary = quick_analyze(&bytes)?;
            print_summary(&summary);
        }
        "detailed" => {
            let analysis = analyze_wasm_module(&bytes)?;
            print_detailed_analysis(&analysis, &matches);
        }
        _ => {
            return Err("Invalid format. Use: json, summary, or detailed.".into());
        }
    }

    Ok(())
}

fn print_summary(summary: &wasm_inspector::ModuleSummary) {
    println!("MODULE SUMMARY");
    println!("━━━━━━━━━━━━━━━━");
    println!("Size: {} bytes", summary.size_bytes);
    println!("Functions: {}", summary.function_count);
    println!("Imports: {}", summary.import_count);
    println!("Exports: {}", summary.export_count);
    println!(
        "Has Memory: {}",
        if summary.has_memory { "Yes" } else { "No" }
    );
    println!(
        "Has Start Function: {}",
        if summary.has_start_function {
            "Yes"
        } else {
            "No"
        }
    );
    println!(
        "Uses WASI: {}",
        if summary.uses_wasi { "Yes" } else { "No" }
    );

    let risk_text = match summary.risk_level {
        RiskLevel::Low => "[LOW]",
        RiskLevel::Medium => "[MEDIUM]",
        RiskLevel::High => "[HIGH]",
        RiskLevel::Critical => "[CRITICAL]",
    };
    println!("Overall Risk Level: {} {:?}", risk_text, summary.risk_level);

    if let Some(ref lang) = summary.estimated_language {
        println!("Detected Language: {}", lang);
    }
    println!();
}

fn print_detailed_analysis(analysis: &ModuleAnalysis, matches: &clap::ArgMatches) {
    let show_all = !matches.get_flag("security")
        && !matches.get_flag("performance")
        && !matches.get_flag("compatibility");

    println!("DETAILED ANALYSIS REPORT");
    println!("========================");

    if show_all || matches.get_flag("security") {
        print_security_analysis(&analysis.security_analysis);
    }

    if show_all || matches.get_flag("performance") {
        print_performance_analysis(&analysis.performance_metrics);
    }

    if show_all {
        print_memory_analysis(&analysis.memory_analysis);
    }

    if show_all || matches.get_flag("compatibility") {
        print_compatibility_analysis(&analysis.compatibility);
    }

    if show_all {
        print_module_structure(&analysis.module_info);
        print_call_graph_summary(&analysis.call_graph);
    }
}

fn print_security_analysis(security: &SecurityAnalysis) {
    println!("\nSECURITY ANALYSIS");
    println!("━━━━━━━━━━━━━━━━━━━━");

    if security.capabilities.is_empty() {
        println!("[INFO] No special capabilities detected.");
    } else {
        println!("Detected Capabilities:");
        for cap in &security.capabilities {
            let risk_text = match cap.risk_level {
                RiskLevel::Low => "[LOW]",
                RiskLevel::Medium => "[MEDIUM]",
                RiskLevel::High => "[HIGH]",
                RiskLevel::Critical => "[CRITICAL]",
            };
            println!("  {} {} - {}", risk_text, cap.name, cap.description);
            if !cap.evidence.is_empty() {
                println!("    Evidence: {}", cap.evidence.join(", "));
            }
        }
    }

    if !security.vulnerabilities.is_empty() {
        println!("\nPotential Vulnerabilities:");
        for vuln in &security.vulnerabilities {
            let severity_text = match vuln.severity {
                RiskLevel::Low => "[LOW]",
                RiskLevel::Medium => "[MEDIUM]",
                RiskLevel::High => "[HIGH]",
                RiskLevel::Critical => "[CRITICAL]",
            };
            println!("  {} {} - {}", severity_text, vuln.id, vuln.description);
            println!("    Location: {}", vuln.location);
        }
    }

    if security.wasi_usage.uses_wasi {
        println!("\nWASI Usage:");
        if let Some(ref version) = security.wasi_usage.wasi_version {
            println!("  Version: {}", version);
        }
        if !security.wasi_usage.required_capabilities.is_empty() {
            println!(
                "  Required Capabilities: {}",
                security.wasi_usage.required_capabilities.join(", ")
            );
        }
    }

    println!("\nSandbox Compatibility:");
    println!(
        "  Browser Safe: {}",
        if security.sandbox_compatibility.browser_safe {
            "Yes"
        } else {
            "No"
        }
    );
    println!(
        "  Node.js Safe: {}",
        if security.sandbox_compatibility.node_safe {
            "Yes"
        } else {
            "No"
        }
    );
    println!(
        "  Cloudflare Workers Safe: {}",
        if security.sandbox_compatibility.cloudflare_workers_safe {
            "Yes"
        } else {
            "No"
        }
    );

    if !security.sandbox_compatibility.restrictions.is_empty() {
        println!("  Restrictions/Considerations:");
        for restriction in &security.sandbox_compatibility.restrictions {
            println!("    - {}", restriction);
        }
    }
    println!();
}

fn print_performance_analysis(perf: &PerformanceMetrics) {
    println!("\nPERFORMANCE ANALYSIS");
    println!("━━━━━━━━━━━━━━━━━━━━━━━");
    println!("Module Size: {} bytes", perf.module_size);
    println!("Code Size (approx.): {} bytes", perf.code_size);
    println!(
        "Estimated Cold Start: {:.2}ms",
        perf.estimated_cold_start_ms
    );
    println!("Complexity Score: {:.1}/100", perf.complexity_score);

    println!("\nMemory Usage (Basic Estimate):");
    println!(
        "  Initial Memory: {}KB",
        perf.memory_usage_estimate.initial_memory_kb
    );
    if let Some(max) = perf.memory_usage_estimate.max_memory_kb {
        println!("  Maximum Memory: {}KB", max);
    } else {
        println!("  Maximum Memory: Not specified");
    }
    println!(
        "  Estimated Max Stack Usage (Locals): {}KB",
        perf.memory_usage_estimate.stack_usage_estimate_kb
    );

    if !perf.optimization_suggestions.is_empty() {
        println!("\nOptimization Suggestions:");
        for suggestion in &perf.optimization_suggestions {
            println!("  - Category: {}", suggestion.category);
            println!("    Description: {}", suggestion.description);
            if let Some(ref savings) = suggestion.potential_savings {
                println!("    Potential Savings: {}", savings);
            }
        }
    }
    println!();
}

fn print_memory_analysis(mem_analysis: &MemoryAnalysisResult) {
    println!("\nDETAILED MEMORY ANALYSIS");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    println!("\nMemory Layout:");
    println!(
        "  Total Initial Size: {} bytes",
        mem_analysis.memory_layout.total_initial_size
    );
    if let Some(max_size) = mem_analysis.memory_layout.total_max_size {
        println!("  Total Max Size: {} bytes", max_size);
    } else {
        println!("  Total Max Size: Unbounded");
    }
    println!(
        "  Data Segments Count: {}",
        mem_analysis.memory_layout.data_segments.len()
    );
    // TODO: Add more details for DataSegmentAnalysis if needed

    println!("\nMemory Operations Summary:");
    println!(
        "  Total Memory Ops: {}",
        mem_analysis.operation_analysis.total_memory_ops
    );
    println!(
        "  Load Operations: {}",
        mem_analysis.operation_analysis.load_operations
    );
    println!(
        "  Store Operations: {}",
        mem_analysis.operation_analysis.store_operations
    );
    println!(
        "  Bulk Operations: {}",
        mem_analysis.operation_analysis.bulk_operations
    );
    println!(
        "  Memory Growth Operations: {}",
        mem_analysis.operation_analysis.memory_growth_operations
    );
    println!(
        "  Operation Density (ops/defined function): {:.2}",
        mem_analysis.operation_analysis.operation_density
    );

    if !mem_analysis.allocation_patterns.is_empty() {
        println!("\nIdentified Allocation Patterns:");
        for pattern in &mem_analysis.allocation_patterns {
            let risk_text = match pattern.risk_assessment.risk_level {
                RiskLevel::Low => "[LOW]",
                RiskLevel::Medium => "[MEDIUM]",
                RiskLevel::High => "[HIGH]",
                RiskLevel::Critical => "[CRITICAL]",
            };
            println!(
                "  - Type: {:?}, Frequency: {}",
                pattern.pattern_type, pattern.frequency
            );
            println!(
                "    Risk: {} - {}",
                risk_text, pattern.risk_assessment.description
            );
            if !pattern.risk_assessment.mitigation_suggestions.is_empty() {
                println!(
                    "    Suggestions: {}",
                    pattern.risk_assessment.mitigation_suggestions.join("; ")
                );
            }
        }
    }

    if !mem_analysis.memory_hotspots.is_empty() {
        println!("\nPotential Memory Hotspots (Top 5):");
        for hotspot in mem_analysis.memory_hotspots.iter().take(5) {
            let func_name = hotspot.function_name.as_deref().unwrap_or("N/A");
            println!(
                "  - Function: {} (Index {})",
                func_name, hotspot.function_index
            );
            println!(
                "    Ops Count: {}, Est. Pressure: {:.2}, Type: {:?}",
                hotspot.operation_count, hotspot.estimated_memory_pressure, hotspot.hotspot_type
            );
        }
    }

    if !mem_analysis.optimization_opportunities.is_empty() {
        println!("\nMemory Optimization Opportunities:");
        for opt in &mem_analysis.optimization_opportunities {
            println!(
                "  - Type: {:?} (Difficulty: {:?})",
                opt.optimization_type, opt.implementation_difficulty
            );
            println!("    Description: {}", opt.description);
            if let Some(savings) = &opt.estimated_savings {
                println!("    Potential Savings: {}", savings);
            }
        }
    }

    println!("\nMemory Safety Analysis:");
    println!(
        "  Uninitialized Access Risk: [{:?}]",
        mem_analysis.safety_analysis.uninitialized_access_risk
    );
    println!(
        "  Memory Leak Risk: [{:?}]",
        mem_analysis.safety_analysis.memory_leak_risk
    );
    println!(
        "  Buffer Safety Score (Heuristic): {:.1}/100",
        mem_analysis.safety_analysis.buffer_safety_score
    );
    if !mem_analysis.safety_analysis.potential_overflows.is_empty() {
        println!("  Potential Overflows/Issues:");
        for overflow in &mem_analysis.safety_analysis.potential_overflows {
            let risk_text = match overflow.risk_level {
                RiskLevel::Low => "[LOW]",
                RiskLevel::Medium => "[MEDIUM]",
                RiskLevel::High => "[HIGH]",
                RiskLevel::Critical => "[CRITICAL]",
            };
            println!(
                "    - Func Idx {}: {} risk for {} - {}",
                overflow.function_index, risk_text, overflow.operation_type, overflow.description
            );
        }
    }
    println!();
}

fn print_compatibility_analysis(compat: &CompatibilityMatrix) {
    println!("\nCOMPATIBILITY ANALYSIS");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━");

    let runtimes = [
        ("Wasmtime", &compat.wasmtime),
        ("Wasmer", &compat.wasmer),
        ("Browser", &compat.browser),
        ("Node.js", &compat.node_js),
        ("Deno", &compat.deno),
        ("Cloudflare Workers", &compat.cloudflare_workers),
    ];

    for (name, status) in &runtimes {
        let status_indicator = if status.compatible {
            "[COMPATIBLE]"
        } else {
            "[ISSUES]"
        };
        println!("{} {}", status_indicator, name);

        if !status.issues.is_empty() {
            println!("    Issues:");
            for issue in &status.issues {
                println!("      - {}", issue);
            }
        }

        if !status.required_features.is_empty() {
            println!("    Required Features:");
            for feature in &status.required_features {
                println!("      - {}", feature);
            }
        }
    }

    if let Some(ref lang) = compat.detected_language {
        println!("\nDetected Source Language (Heuristic): {}", lang);
    }
    println!();
}

fn print_module_structure(module: &ModuleInfo) {
    println!("\nMODULE STRUCTURE");
    println!("━━━━━━━━━━━━━━━━━━━");
    println!("WASM Version: {}", module.version);

    let imported_func_count = module
        .imports
        .iter()
        .filter(|i| matches!(i.kind, wasm_inspector::ImportKind::Function { .. }))
        .count();
    let defined_func_count = module.functions.len();
    let total_func_count = imported_func_count + defined_func_count;
    let exported_func_count = module
        .exports
        .iter()
        .filter(|e| matches!(e.kind, wasm_inspector::ExportKind::Function))
        .count();

    println!(
        "Functions: {} ({} imported, {} defined, {} exported)",
        total_func_count, imported_func_count, defined_func_count, exported_func_count
    );

    println!("Type Signatures: {}", module.type_signatures.len());
    println!("Imports: {} total", module.imports.len());
    println!("Exports: {} total", module.exports.len());
    println!("Globals: {}", module.globals.len());
    println!("Tables: {}", module.tables.len());
    println!("Data Segments: {}", module.data_segments.len());
    println!("Element Segments: {}", module.element_segments.len());
    println!("Custom Sections: {}", module.custom_sections.len());

    if let Some(start_idx) = module.start_function {
        // Make start_func_name a String
        let start_func_name: String = module
            .functions
            .iter()
            .find(|f| f.index == start_idx)
            .and_then(|f| f.name.as_ref().map(|s| s.to_string())) // If found, clone to String
            .unwrap_or_else(|| {
                // This closure must return String
                // Logic to find the imported function by global start_idx
                let mut current_global_idx_for_imports = 0;
                module
                    .imports
                    .iter()
                    .find_map(|i| {
                        if let wasm_inspector::ImportKind::Function { .. } = i.kind {
                            if current_global_idx_for_imports == start_idx {
                                Some(format!("{}::{} (import)", i.module, i.name)) // Return String
                            } else {
                                current_global_idx_for_imports += 1;
                                None
                            }
                        } else {
                            None
                        }
                    })
                    .unwrap_or_else(|| format!("func_{}", start_idx)) // Return String
            });
        println!("Start Function: {} (Index {})", start_func_name, start_idx);
    }

    if let Some(ref memory) = module.memory {
        print!("Memory: {} pages initial", memory.initial);
        if let Some(max) = memory.maximum {
            print!(", {} pages maximum", max);
        }
        if memory.shared {
            print!(" (shared)");
        }
        println!();
    } else {
        println!("Memory: Not defined");
    }

    if !module.exports.is_empty() {
        println!("\nKey Exports (up to 10):");
        for export in module.exports.iter().take(10) {
            println!(
                "  - Name: \"{}\", Kind: {:?}, Index: {}",
                export.name, export.kind, export.index
            );
        }
        if module.exports.len() > 10 {
            println!("  ... and {} more export(s)", module.exports.len() - 10);
        }
    }

    if !module.imports.is_empty() {
        println!("\nKey Imports (up to 10):");
        for import in module.imports.iter().take(10) {
            println!(
                "  - From: \"{}\", Name: \"{}\", Kind: {:?}",
                import.module, import.name, import.kind
            );
        }
        if module.imports.len() > 10 {
            println!("  ... and {} more import(s)", module.imports.len() - 10);
        }
    }
    println!();
}

fn print_call_graph_summary(call_graph: &CallGraph) {
    println!("\nCALL GRAPH SUMMARY");
    println!("━━━━━━━━━━━━━━━━━━━━━");
    println!("Nodes (Functions in Graph): {}", call_graph.nodes.len());
    println!("Edges (Calls): {}", call_graph.edges.len());
    if call_graph.entry_points.is_empty() {
        println!("Entry Points: None identified (or only implicit)");
    } else {
        println!(
            "Entry Points (Global Indices): {:?}",
            call_graph.entry_points
        );
    }

    if !call_graph.unreachable_functions.is_empty() {
        println!(
            "Unreachable Defined Functions (Potential Dead Code): {}",
            call_graph.unreachable_functions.len()
        );
        if call_graph.unreachable_functions.len() <= 10 {
            println!("  Indices: {:?}", call_graph.unreachable_functions);
            // Optionally print names if few and nodes are rich enough
            // for func_idx in &call_graph.unreachable_functions {
            //     if let Some(node) = call_graph.nodes.iter().find(|n| n.function_index == *func_idx) {
            //         println!("    - {} (Index {})", node.name.as_deref().unwrap_or("N/A"), func_idx);
            //     }
            // }
        } else {
            println!(
                "  First 10 Indices: {:?}",
                call_graph
                    .unreachable_functions
                    .iter()
                    .take(10)
                    .collect::<Vec<_>>()
            );
        }
    } else {
        println!("Unreachable Defined Functions: None found.");
    }

    let mut most_called: Vec<_> = call_graph
        .nodes
        .iter()
        .filter(|n| n.call_count > 0 && !n.is_imported)
        .collect();
    most_called.sort_by(|a, b| b.call_count.cmp(&a.call_count));

    if !most_called.is_empty() {
        println!("\nMost Called Defined Functions (Top 5 by incoming calls):");
        for node in most_called.iter().take(5) {
            let func_name = node.name.as_deref().unwrap_or("N/A");
            println!(
                "  - Name: \"{}\" (Index {}), Called {} times",
                func_name, node.function_index, node.call_count
            );
        }
    }
    println!();
}
