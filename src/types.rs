// types.rs
use serde::{Deserialize, Serialize}; // Make sure this is present
use crate::memory::MemoryAnalysisResult;

#[derive(Debug, Clone, Serialize, Deserialize)] // CHECKED
pub struct ModuleAnalysis {
    pub module_info: ModuleInfo,                 // CHECKED (ModuleInfo below)
    pub call_graph: CallGraph,                 // CHECKED (CallGraph below)
    pub security_analysis: SecurityAnalysis,     // CHECKED (SecurityAnalysis below)
    pub performance_metrics: PerformanceMetrics, // CHECKED (PerformanceMetrics below)
    pub compatibility: CompatibilityMatrix,      // CHECKED (CompatibilityMatrix below)
    pub memory_analysis: MemoryAnalysisResult,   // CHECKED (MemoryAnalysisResult in memory.rs, all sub-fields checked)
}

#[derive(Debug, Clone, Serialize, Deserialize)] // CHECKED
pub struct ModuleInfo {
    pub version: u32,
    pub imports: Vec<Import>,                   // CHECKED (Import below)
    pub exports: Vec<Export>,                   // CHECKED (Export below)
    pub functions: Vec<Function>,               // CHECKED (Function below)
    pub memory: Option<Memory>,                 // CHECKED (Memory below)
    pub tables: Vec<Table>,                     // CHECKED (Table below)
    pub globals: Vec<Global>,                   // CHECKED (Global below)
    pub data_segments: Vec<DataSegment>,        // CHECKED (DataSegment below)
    pub element_segments: Vec<ElementSegment>,  // CHECKED (ElementSegment below)
    pub start_function: Option<u32>,
    pub custom_sections: Vec<CustomSection>,    // CHECKED (CustomSection below)
    pub function_call_instructions: Vec<(u32, u32)>, // Tuples of u32 are fine
    pub type_signatures: Vec<String>,           // Vec<String> is fine
}

#[derive(Debug, Clone, Serialize, Deserialize)] // CHECKED
pub struct Import {
    pub module: String,
    pub name: String,
    pub kind: ImportKind,                       // CHECKED (ImportKind enum below)
    pub index: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)] // CHECKED
pub enum ImportKind {
    Function { type_index: u32 },
    Table { table_type: TableType },           // CHECKED (TableType below)
    Memory { memory_type: MemoryType },         // CHECKED (MemoryType below)
    Global { global_type: GlobalType },         // CHECKED (GlobalType below)
}

#[derive(Debug, Clone, Serialize, Deserialize)] // CHECKED
pub struct Export {
    pub name: String,
    pub kind: ExportKind,                       // CHECKED (ExportKind enum below)
    pub index: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)] // CHECKED
#[derive(PartialEq, Eq)]
pub enum ExportKind {
    Function,
    Table,
    Memory,
    Global,
}

#[derive(Debug, Clone, Serialize, Deserialize)] // CHECKED
pub struct Function {
    pub index: u32,
    pub type_index: u32,
    pub locals: Vec<LocalType>,                 // CHECKED (LocalType below)
    pub body_size: u32,
    pub is_imported: bool,
    pub is_exported: bool,
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)] // CHECKED
pub struct Memory {
    pub initial: u32,
    pub maximum: Option<u32>,
    pub shared: bool,
    pub is_imported: bool,
    pub is_exported: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)] // CHECKED
pub struct Table {
    pub index: u32,
    pub table_type: TableType,                  // CHECKED (TableType below)
    pub is_imported: bool,
    pub is_exported: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)] // CHECKED
pub struct TableType {
    pub element_type: String,
    pub initial: u32,
    pub maximum: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)] // CHECKED
pub struct MemoryType {
    pub initial: u32,
    pub maximum: Option<u32>,
    pub shared: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)] // CHECKED
pub struct Global {
    pub index: u32,
    pub global_type: GlobalType,                // CHECKED (GlobalType below)
    pub init_value: Option<String>,
    pub is_imported: bool,
    pub is_exported: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)] // CHECKED
pub struct GlobalType {
    pub value_type: String,
    pub mutable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)] // CHECKED
pub struct LocalType {
    pub count: u32,
    pub value_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)] // CHECKED
pub struct DataSegment {
    pub index: u32,
    pub memory_index: u32,
    pub offset: u32,
    pub size: u32,
    pub is_passive: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)] // CHECKED
pub struct ElementSegment {
    pub index: u32,
    pub table_index: Option<u32>,
    pub offset: Option<u32>,
    pub element_count: u32,
    pub is_passive: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)] // CHECKED
pub struct CustomSection {
    pub name: String,
    pub size: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)] // CHECKED
pub struct CallGraph {
    pub nodes: Vec<CallNode>,                   // CHECKED (CallNode below)
    pub edges: Vec<CallEdge>,                   // CHECKED (CallEdge below)
    pub entry_points: Vec<u32>,
    pub unreachable_functions: Vec<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)] // CHECKED
pub struct CallNode {
    pub function_index: u32,
    pub name: Option<String>,
    pub is_imported: bool,
    pub is_exported: bool,
    pub call_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)] // CHECKED
pub struct CallEdge {
    pub from: u32,
    pub to: u32,
    pub call_sites: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)] // CHECKED
pub struct SecurityAnalysis {
    pub capabilities: Vec<Capability>,          // CHECKED (Capability below)
    pub vulnerabilities: Vec<Vulnerability>,    // CHECKED (Vulnerability below)
    pub sandbox_compatibility: SandboxCompatibility, // CHECKED (SandboxCompatibility below)
    pub wasi_usage: WasiUsage,                  // CHECKED (WasiUsage below)
}

#[derive(Debug, Clone, Serialize, Deserialize)] // CHECKED
pub struct Capability {
    pub name: String,
    pub description: String,
    pub risk_level: RiskLevel,                  // CHECKED (RiskLevel enum below)
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)] // CHECKED
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)] // CHECKED
pub struct Vulnerability {
    pub id: String,
    pub description: String,
    pub severity: RiskLevel,                    // CHECKED (RiskLevel enum above)
    pub location: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)] // CHECKED
pub struct SandboxCompatibility {
    pub browser_safe: bool,
    pub node_safe: bool,
    pub cloudflare_workers_safe: bool,
    pub restrictions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)] // CHECKED
pub struct WasiUsage {
    pub uses_wasi: bool,
    pub wasi_version: Option<String>,
    pub required_capabilities: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)] // CHECKED
pub struct PerformanceMetrics {
    pub module_size: u32,
    pub code_size: u32,
    pub estimated_cold_start_ms: f64,
    pub complexity_score: f64,
    pub memory_usage_estimate: MemoryUsageEstimate, // CHECKED (MemoryUsageEstimate below)
    pub optimization_suggestions: Vec<OptimizationSuggestion>, // CHECKED (OptimizationSuggestion below)
}

#[derive(Debug, Clone, Serialize, Deserialize)] // CHECKED
pub struct MemoryUsageEstimate {
    pub initial_memory_kb: u32,
    pub max_memory_kb: Option<u32>,
    pub stack_usage_estimate_kb: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)] // CHECKED
pub struct OptimizationSuggestion {
    pub category: String,
    pub description: String,
    pub potential_savings: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)] // CHECKED
pub struct CompatibilityMatrix {
    pub wasmtime: CompatibilityStatus,          // CHECKED (CompatibilityStatus below)
    pub wasmer: CompatibilityStatus,            // CHECKED
    pub browser: CompatibilityStatus,           // CHECKED
    pub node_js: CompatibilityStatus,           // CHECKED
    pub deno: CompatibilityStatus,              // CHECKED
    pub cloudflare_workers: CompatibilityStatus, // CHECKED
    pub detected_language: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)] // CHECKED
pub struct CompatibilityStatus {
    pub compatible: bool,
    pub issues: Vec<String>,
    pub required_features: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)] // CHECKED
pub struct ModuleSummary {
    pub size_bytes: u32,
    pub function_count: u32,
    pub import_count: u32,
    pub export_count: u32,
    pub has_memory: bool,
    pub has_start_function: bool,
    pub uses_wasi: bool,
    pub risk_level: RiskLevel,                  // CHECKED
    pub estimated_language: Option<String>,
}

impl From<ModuleAnalysis> for ModuleSummary { // No Serialize needed here
    fn from(analysis: ModuleAnalysis) -> Self {
        let imported_func_count = analysis.module_info.imports.iter().filter(|i| matches!(i.kind, ImportKind::Function{..})).count();
        let defined_func_count = analysis.module_info.functions.len();
        let total_function_count = (imported_func_count + defined_func_count) as u32;

        Self {
            size_bytes: analysis.performance_metrics.module_size,
            function_count: total_function_count,
            import_count: analysis.module_info.imports.len() as u32,
            export_count: analysis.module_info.exports.len() as u32,
            has_memory: analysis.module_info.memory.is_some(),
            has_start_function: analysis.module_info.start_function.is_some(),
            uses_wasi: analysis.security_analysis.wasi_usage.uses_wasi,
            risk_level: analysis
                .security_analysis
                .capabilities
                .iter()
                .map(|c| &c.risk_level)
                .max()
                .cloned()
                .unwrap_or(RiskLevel::Low),
            estimated_language: analysis.compatibility.detected_language,
        }
    }
}