// ===== memory.rs =====
// src/memory.rs
use crate::types::*;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use wasmparser::{FunctionBody, Operator}; 

pub struct MemoryAnalyzer<'a> {
    module_info: &'a ModuleInfo,
    wasm_bytes: &'a [u8],
    memory_operations: HashMap<u32, Vec<MemoryOperation>>, // Key: global function index
    allocation_patterns: Vec<AllocationPattern>,
}

#[derive(Debug, Clone, Serialize, Deserialize)] // OK
pub struct MemoryOperation {
    pub operation_type: MemoryOpType,
    pub offset: Option<u32>,
    pub size: Option<u32>,
    pub function_index: u32,
    pub instruction_offset: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)] // OK
pub enum MemoryOpType {
    Load { size_bytes: u32 },
    Store { size_bytes: u32 },
    MemorySize,
    MemoryGrow,
    MemoryCopy,
    MemoryFill,
}

#[derive(Debug, Clone, Serialize, Deserialize)] // OK
pub struct AllocationPattern {
    pub pattern_type: AllocationType,
    pub frequency: u32,
    pub average_size: u32,
    pub functions_involved: Vec<u32>,
    pub risk_assessment: MemoryRisk,
}

#[derive(Debug, Clone, Serialize, Deserialize)] // OK
pub enum AllocationType {
    StaticAllocation,
    DynamicGrowth,
    BulkOperations,
    FrequentSmallAllocations,
    LargeAllocations,
}

#[derive(Debug, Clone, Serialize, Deserialize)] // OK
pub struct MemoryRisk {
    pub risk_level: RiskLevel, // This comes from types.rs, which derives Serialize
    pub description: String,
    pub mitigation_suggestions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)] // OK
pub struct MemoryAnalysisResult {
    pub memory_layout: MemoryLayout,
    pub operation_analysis: MemoryOperationAnalysis,
    pub allocation_patterns: Vec<AllocationPattern>,
    pub memory_hotspots: Vec<MemoryHotspot>,
    pub optimization_opportunities: Vec<MemoryOptimization>,
    pub safety_analysis: MemorySafetyAnalysis,
}

#[derive(Debug, Clone, Serialize, Deserialize)] // OK
pub struct MemoryLayout {
    pub total_initial_size: u32,
    pub total_max_size: Option<u32>,
    pub data_segments: Vec<DataSegmentAnalysis>,
    pub stack_estimation: StackAnalysis,
    pub heap_estimation: HeapAnalysis,
}

#[derive(Debug, Clone, Serialize, Deserialize)] // OK
pub struct DataSegmentAnalysis {
    pub index: u32,
    pub size: u32,
    pub is_active: bool,
    pub estimated_usage: DataUsagePattern,
}

#[derive(Debug, Clone, Serialize, Deserialize)] // OK
pub enum DataUsagePattern {
    ConstantData,
    LookupTable,
    InitializedVariables,
    StringLiterals,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)] // OK
pub struct StackAnalysis {
    pub estimated_max_depth: u32,
    pub recursive_risk: bool,
    pub deep_call_chains: Vec<Vec<u32>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)] // OK
pub struct HeapAnalysis {
    pub uses_dynamic_allocation: bool,
    pub allocation_functions: Vec<String>,
    pub estimated_heap_usage: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)] // OK
pub struct MemoryOperationAnalysis {
    pub total_memory_ops: u32,
    pub load_operations: u32,
    pub store_operations: u32,
    pub bulk_operations: u32,
    pub memory_growth_operations: u32,
    pub operation_density: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)] // OK
pub struct MemoryHotspot {
    pub function_index: u32,
    pub function_name: Option<String>,
    pub operation_count: u32,
    pub estimated_memory_pressure: f64,
    pub hotspot_type: HotspotType,
}

#[derive(Debug, Clone, Serialize, Deserialize)] // OK
pub enum HotspotType {
    HighFrequencyAccess,
    LargeDataMovement,
    MemoryGrowth,
    PotentialLeaks,
}

#[derive(Debug, Clone, Serialize, Deserialize)] // OK
pub struct MemoryOptimization {
    pub optimization_type: OptimizationType,
    pub description: String,
    pub estimated_savings: Option<String>,
    pub implementation_difficulty: DifficultyLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)] // OK
pub enum OptimizationType {
    ReduceMemoryFootprint,
    OptimizeDataLayout,
    MinimizeAllocations,
    ImproveLocality,
    SetMemoryLimits,
}

#[derive(Debug, Clone, Serialize, Deserialize)] // OK
pub enum DifficultyLevel {
    Easy,
    Medium,
    Hard,
}

#[derive(Debug, Clone, Serialize, Deserialize)] // OK
pub struct MemorySafetyAnalysis {
    pub potential_overflows: Vec<PotentialOverflow>,
    pub uninitialized_access_risk: RiskLevel, // From types.rs
    pub memory_leak_risk: RiskLevel,          // From types.rs
    pub buffer_safety_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)] // OK
pub struct PotentialOverflow {
    pub function_index: u32,
    pub operation_type: String,
    pub risk_level: RiskLevel, // From types.rs
    pub description: String,
}

const WASM_PAGE_SIZE_BYTES: u32 = 64 * 1024;

impl<'a> MemoryAnalyzer<'a> {
    pub fn new(module_info: &'a ModuleInfo, wasm_bytes: &'a [u8]) -> Self {
        Self {
            module_info,
            wasm_bytes,
            memory_operations: HashMap::new(),
            allocation_patterns: Vec::new(),
        }
    }

    pub fn analyze(&mut self) -> Result<MemoryAnalysisResult> {
        self.extract_memory_operations()?;
        self.analyze_allocation_patterns(); // Uses self.memory_operations

        let memory_layout = self.analyze_memory_layout();
        let operation_analysis = self.analyze_operations_summary(); // Renamed from analyze_operations
        let memory_hotspots = self.find_memory_hotspots();
        let optimization_opportunities = self.identify_optimizations();
        let safety_analysis = self.analyze_memory_safety();

        Ok(MemoryAnalysisResult {
            memory_layout,
            operation_analysis,
            allocation_patterns: self.allocation_patterns.clone(),
            memory_hotspots,
            optimization_opportunities,
            safety_analysis,
        })
    }

    fn extract_memory_operations(&mut self) -> Result<()> {
        use wasmparser::{Parser, Payload};

        let parser = Parser::new(0);
        let mut defined_function_idx_counter = 0; // Index for functions defined in the module

        // Calculate the number of imported functions to correctly map to global function indices
        let imported_function_count = self
            .module_info
            .imports
            .iter()
            .filter(|i| matches!(i.kind, ImportKind::Function { .. }))
            .count() as u32;

        for payload_result in parser.parse_all(self.wasm_bytes) {
            let payload = payload_result?;
            if let Payload::CodeSectionEntry(body) = payload {
                let current_func_global_idx =
                    imported_function_count + defined_function_idx_counter;
                self.analyze_function_body_for_memory_ops(current_func_global_idx, &body)?;
                defined_function_idx_counter += 1;
            }
        }
        Ok(())
    }

    fn analyze_function_body_for_memory_ops(
        &mut self,
        func_global_idx: u32,
        body: &FunctionBody,
    ) -> Result<()> {
        let mut reader = body.get_operators_reader()?;
        let mut instruction_offset_counter: u32;
        let mut operations_for_func = Vec::new();

        while !reader.eof() {
            let op_pos = reader.original_position();
            let op = reader.read()?;
            instruction_offset_counter = op_pos as u32; // Using original_position as offset

            let mem_op = match op {
                Operator::I32Load { memarg } => Some(MemoryOperation {
                    operation_type: MemoryOpType::Load { size_bytes: 4 },
                    offset: Some(memarg.offset as u32),
                    size: Some(4),
                    function_index: func_global_idx,
                    instruction_offset: instruction_offset_counter,
                }),
                Operator::I64Load { memarg } => Some(MemoryOperation {
                    operation_type: MemoryOpType::Load { size_bytes: 8 },
                    offset: Some(memarg.offset as u32),
                    size: Some(8),
                    function_index: func_global_idx,
                    instruction_offset: instruction_offset_counter,
                }),
                Operator::F32Load { memarg } => Some(MemoryOperation {
                    operation_type: MemoryOpType::Load { size_bytes: 4 },
                    offset: Some(memarg.offset as u32),
                    size: Some(4),
                    function_index: func_global_idx,
                    instruction_offset: instruction_offset_counter,
                }),
                Operator::F64Load { memarg } => Some(MemoryOperation {
                    operation_type: MemoryOpType::Load { size_bytes: 8 },
                    offset: Some(memarg.offset as u32),
                    size: Some(8),
                    function_index: func_global_idx,
                    instruction_offset: instruction_offset_counter,
                }),
                Operator::I32Load8S { memarg } | Operator::I32Load8U { memarg } => {
                    Some(MemoryOperation {
                        operation_type: MemoryOpType::Load { size_bytes: 1 },
                        offset: Some(memarg.offset as u32),
                        size: Some(1),
                        function_index: func_global_idx,
                        instruction_offset: instruction_offset_counter,
                    })
                }
                Operator::I32Load16S { memarg } | Operator::I32Load16U { memarg } => {
                    Some(MemoryOperation {
                        operation_type: MemoryOpType::Load { size_bytes: 2 },
                        offset: Some(memarg.offset as u32),
                        size: Some(2),
                        function_index: func_global_idx,
                        instruction_offset: instruction_offset_counter,
                    })
                }
                Operator::I64Load8S { memarg } | Operator::I64Load8U { memarg } => {
                    Some(MemoryOperation {
                        operation_type: MemoryOpType::Load { size_bytes: 1 },
                        offset: Some(memarg.offset as u32),
                        size: Some(1),
                        function_index: func_global_idx,
                        instruction_offset: instruction_offset_counter,
                    })
                }
                Operator::I64Load16S { memarg } | Operator::I64Load16U { memarg } => {
                    Some(MemoryOperation {
                        operation_type: MemoryOpType::Load { size_bytes: 2 },
                        offset: Some(memarg.offset as u32),
                        size: Some(2),
                        function_index: func_global_idx,
                        instruction_offset: instruction_offset_counter,
                    })
                }
                Operator::I64Load32S { memarg } | Operator::I64Load32U { memarg } => {
                    Some(MemoryOperation {
                        operation_type: MemoryOpType::Load { size_bytes: 4 },
                        offset: Some(memarg.offset as u32),
                        size: Some(4),
                        function_index: func_global_idx,
                        instruction_offset: instruction_offset_counter,
                    })
                }

                Operator::I32Store { memarg } => Some(MemoryOperation {
                    operation_type: MemoryOpType::Store { size_bytes: 4 },
                    offset: Some(memarg.offset as u32),
                    size: Some(4),
                    function_index: func_global_idx,
                    instruction_offset: instruction_offset_counter,
                }),
                Operator::I64Store { memarg } => Some(MemoryOperation {
                    operation_type: MemoryOpType::Store { size_bytes: 8 },
                    offset: Some(memarg.offset as u32),
                    size: Some(8),
                    function_index: func_global_idx,
                    instruction_offset: instruction_offset_counter,
                }),
                Operator::F32Store { memarg } => Some(MemoryOperation {
                    operation_type: MemoryOpType::Store { size_bytes: 4 },
                    offset: Some(memarg.offset as u32),
                    size: Some(4),
                    function_index: func_global_idx,
                    instruction_offset: instruction_offset_counter,
                }),
                Operator::F64Store { memarg } => Some(MemoryOperation {
                    operation_type: MemoryOpType::Store { size_bytes: 8 },
                    offset: Some(memarg.offset as u32),
                    size: Some(8),
                    function_index: func_global_idx,
                    instruction_offset: instruction_offset_counter,
                }),
                Operator::I32Store8 { memarg } | Operator::I64Store8 { memarg } => {
                    Some(MemoryOperation {
                        operation_type: MemoryOpType::Store { size_bytes: 1 },
                        offset: Some(memarg.offset as u32),
                        size: Some(1),
                        function_index: func_global_idx,
                        instruction_offset: instruction_offset_counter,
                    })
                }
                Operator::I32Store16 { memarg } | Operator::I64Store16 { memarg } => {
                    Some(MemoryOperation {
                        operation_type: MemoryOpType::Store { size_bytes: 2 },
                        offset: Some(memarg.offset as u32),
                        size: Some(2),
                        function_index: func_global_idx,
                        instruction_offset: instruction_offset_counter,
                    })
                }
                Operator::I64Store32 { memarg } => Some(MemoryOperation {
                    operation_type: MemoryOpType::Store { size_bytes: 4 },
                    offset: Some(memarg.offset as u32),
                    size: Some(4),
                    function_index: func_global_idx,
                    instruction_offset: instruction_offset_counter,
                }),

                Operator::MemorySize { .. } => Some(MemoryOperation {
                    operation_type: MemoryOpType::MemorySize,
                    offset: None,
                    size: None,
                    function_index: func_global_idx,
                    instruction_offset: instruction_offset_counter,
                }),
                Operator::MemoryGrow { .. } => Some(MemoryOperation {
                    operation_type: MemoryOpType::MemoryGrow,
                    offset: None,
                    size: None,
                    function_index: func_global_idx,
                    instruction_offset: instruction_offset_counter,
                }),
                Operator::MemoryCopy { .. } => Some(MemoryOperation {
                    operation_type: MemoryOpType::MemoryCopy,
                    offset: None,
                    size: None,
                    function_index: func_global_idx,
                    instruction_offset: instruction_offset_counter,
                }),
                Operator::MemoryFill { .. } => Some(MemoryOperation {
                    operation_type: MemoryOpType::MemoryFill,
                    offset: None,
                    size: None,
                    function_index: func_global_idx,
                    instruction_offset: instruction_offset_counter,
                }),
                _ => None,
            };
            if let Some(op) = mem_op {
                operations_for_func.push(op);
            }
        }
        if !operations_for_func.is_empty() {
            self.memory_operations
                .insert(func_global_idx, operations_for_func);
        }
        Ok(())
    }

    fn analyze_allocation_patterns(&mut self) {
        let mut growth_functions = HashSet::new();
        let mut bulk_op_functions = HashSet::new();
        let mut frequent_small_access_funcs = HashSet::new();

        for (&func_idx, operations) in &self.memory_operations {
            let mut small_access_count = 0;
            for op in operations {
                match op.operation_type {
                    MemoryOpType::MemoryGrow => {
                        growth_functions.insert(func_idx);
                    }
                    MemoryOpType::MemoryCopy | MemoryOpType::MemoryFill => {
                        bulk_op_functions.insert(func_idx);
                    }
                    MemoryOpType::Load { size_bytes } | MemoryOpType::Store { size_bytes } => {
                        if size_bytes <= 8 {
                            small_access_count += 1;
                        }
                    }
                    _ => {}
                }
            }
            if small_access_count > 10 {
                // Heuristic: >10 small accesses = frequent
                frequent_small_access_funcs.insert(func_idx);
            }
        }

        if !growth_functions.is_empty() {
            self.allocation_patterns.push(AllocationPattern {
                pattern_type: AllocationType::DynamicGrowth,
                frequency: growth_functions.len() as u32,
                average_size: 0, // Hard to determine statically, could be improved with taint analysis
                functions_involved: growth_functions.into_iter().collect(),
                risk_assessment: MemoryRisk {
                    risk_level: RiskLevel::Medium,
                    description: "Module uses memory.grow for dynamic resizing.".to_string(),
                    mitigation_suggestions: vec![
                        "Set maximum memory limits if possible.".to_string(),
                        "Profile memory usage.".to_string(),
                    ],
                },
            });
        }
        if !bulk_op_functions.is_empty() {
            self.allocation_patterns.push(AllocationPattern {
                pattern_type: AllocationType::BulkOperations,
                frequency: bulk_op_functions.len() as u32,
                average_size: 0, // Hard to determine statically
                functions_involved: bulk_op_functions.into_iter().collect(),
                risk_assessment: MemoryRisk {
                    risk_level: RiskLevel::Low,
                    description: "Module uses bulk memory operations (copy/fill).".to_string(),
                    mitigation_suggestions: vec![
                        "Ensure operations are on valid memory regions.".to_string(),
                    ],
                },
            });
        }
        if !frequent_small_access_funcs.is_empty() {
            self.allocation_patterns.push(AllocationPattern {
                pattern_type: AllocationType::FrequentSmallAllocations, // Or "FrequentSmallAccesses"
                frequency: frequent_small_access_funcs.len() as u32,
                average_size: 4, // Typical small access size
                functions_involved: frequent_small_access_funcs.into_iter().collect(),
                risk_assessment: MemoryRisk {
                    risk_level: RiskLevel::Low,
                    description: "Module performs frequent small memory accesses.".to_string(),
                    mitigation_suggestions: vec![
                        "Consider data layout for cache efficiency.".to_string(),
                        "Batch operations if applicable.".to_string(),
                    ],
                },
            });
        }
        // Static Allocation (from data segments)
        if !self.module_info.data_segments.is_empty() {
            let total_static_size: u32 = self
                .module_info
                .data_segments
                .iter()
                .map(|ds| ds.size)
                .sum();
            self.allocation_patterns.push(AllocationPattern {
                pattern_type: AllocationType::StaticAllocation,
                frequency: self.module_info.data_segments.len() as u32,
                average_size: if !self.module_info.data_segments.is_empty() {
                    total_static_size / self.module_info.data_segments.len() as u32
                } else {
                    0
                },
                functions_involved: vec![], // Not tied to specific functions directly
                risk_assessment: MemoryRisk {
                    risk_level: RiskLevel::Low,
                    description: "Module uses static data segments for initial memory content."
                        .to_string(),
                    mitigation_suggestions: vec![],
                },
            });
        }
    }

    fn analyze_memory_layout(&self) -> MemoryLayout {
        let (total_initial_size, total_max_size) =
            if let Some(ref memory_info) = self.module_info.memory {
                (
                    memory_info.initial * WASM_PAGE_SIZE_BYTES,
                    memory_info.maximum.map(|m| m * WASM_PAGE_SIZE_BYTES),
                )
            } else {
                (0, None)
            };

        let data_segments = self
            .module_info
            .data_segments
            .iter()
            .map(|ds| DataSegmentAnalysis {
                index: ds.index,
                size: ds.size,
                is_active: !ds.is_passive,
                estimated_usage: DataUsagePattern::Unknown, // TODO: Implement better heuristics
            })
            .collect();

        MemoryLayout {
            total_initial_size,
            total_max_size,
            data_segments,
            stack_estimation: self.analyze_stack_usage(),
            heap_estimation: self.analyze_heap_usage(),
        }
    }

    fn analyze_stack_usage(&self) -> StackAnalysis {
        // Simplified: estimate max locals size for any single function
        let estimated_max_depth = self
            .module_info
            .functions
            .iter()
            .map(|f| {
                f.locals
                    .iter()
                    .map(|l| {
                        let type_size = match l.value_type.as_str() {
                            "i32" | "f32" => 4,
                            "i64" | "f64" => 8,
                            _ => 4, // Default for other types like v128 (though it's 16) or refs
                        };
                        l.count * type_size
                    })
                    .sum::<u32>()
            })
            .max()
            .unwrap_or(0);

        // Recursive risk needs call graph analysis, which is separate.
        // For now, set to false or use a simple heuristic.
        StackAnalysis {
            estimated_max_depth,      // This is locals, not true stack depth
            recursive_risk: false,    // Placeholder
            deep_call_chains: vec![], // Placeholder
        }
    }

    fn analyze_heap_usage(&self) -> HeapAnalysis {
        let allocation_functions: Vec<String> = self
            .module_info
            .imports
            .iter()
            .filter(|imp| {
                imp.name.contains("alloc")
                    || imp.name.contains("malloc")
                    || imp.name.contains("free")
            })
            .map(|imp| format!("{}::{}", imp.module, imp.name))
            .collect();

        let uses_dynamic_allocation = !allocation_functions.is_empty()
            || self.memory_operations.values().any(|ops| {
                ops.iter()
                    .any(|op| matches!(op.operation_type, MemoryOpType::MemoryGrow))
            });

        // Very rough estimate of heap usage
        let estimated_heap_usage = if uses_dynamic_allocation {
            self.module_info
                .memory
                .as_ref()
                .map_or(0, |m| m.initial * WASM_PAGE_SIZE_BYTES / 2) // Assume up to half of initial for heap
        } else {
            0
        };

        HeapAnalysis {
            uses_dynamic_allocation,
            allocation_functions,
            estimated_heap_usage,
        }
    }

    fn analyze_operations_summary(&self) -> MemoryOperationAnalysis {
        let mut total_ops = 0;
        let mut load_ops = 0;
        let mut store_ops = 0;
        let mut bulk_ops = 0;
        let mut growth_ops = 0;

        for ops_in_func in self.memory_operations.values() {
            total_ops += ops_in_func.len() as u32;
            for op in ops_in_func {
                match op.operation_type {
                    MemoryOpType::Load { .. } => load_ops += 1,
                    MemoryOpType::Store { .. } => store_ops += 1,
                    MemoryOpType::MemoryCopy | MemoryOpType::MemoryFill => bulk_ops += 1,
                    MemoryOpType::MemoryGrow => growth_ops += 1,
                    MemoryOpType::MemorySize => {} // Not counted as modifying or heavy access
                }
            }
        }
        let defined_func_count = self.module_info.functions.len();
        MemoryOperationAnalysis {
            total_memory_ops: total_ops,
            load_operations: load_ops,
            store_operations: store_ops,
            bulk_operations: bulk_ops,
            memory_growth_operations: growth_ops,
            operation_density: if defined_func_count > 0 {
                total_ops as f64 / defined_func_count as f64
            } else {
                0.0
            },
        }
    }

    fn find_memory_hotspots(&self) -> Vec<MemoryHotspot> {
        let mut hotspots = Vec::new();
        for (&func_idx, operations) in &self.memory_operations {
            if operations.is_empty() {
                continue;
            }

            let operation_count = operations.len() as u32;
            let mut pressure_score = 0.0;
            let mut has_grow = false;
            let mut bulk_op_count = 0;

            for op in operations {
                match op.operation_type {
                    MemoryOpType::Load { size_bytes } | MemoryOpType::Store { size_bytes } => {
                        pressure_score += size_bytes as f64
                    }
                    MemoryOpType::MemoryGrow => {
                        pressure_score += 100.0;
                        has_grow = true;
                    }
                    MemoryOpType::MemoryCopy | MemoryOpType::MemoryFill => {
                        pressure_score += 50.0;
                        bulk_op_count += 1;
                    }
                    _ => {}
                }
            }
            // Normalize pressure or use threshold
            if operation_count > 20 || pressure_score > 100.0 {
                // Heuristic thresholds
                let function_name = self
                    .module_info
                    .functions
                    .iter()
                    .find(|f| f.index == func_idx)
                    .and_then(|f| f.name.clone())
                    .or_else(|| {
                        self.module_info
                            .imports
                            .iter()
                            .enumerate()
                            .filter(|(_, imp)| matches!(imp.kind, ImportKind::Function { .. }))
                            .nth(func_idx as usize) // This assumes func_idx for imports is its sequence number among func imports
                            .map(|(_, imp)| format!("{}::{} (import)", imp.module, imp.name))
                    });

                let hotspot_type = if has_grow {
                    HotspotType::MemoryGrowth
                } else if bulk_op_count > operation_count / 4 {
                    HotspotType::LargeDataMovement
                } else {
                    HotspotType::HighFrequencyAccess
                };

                hotspots.push(MemoryHotspot {
                    function_index: func_idx,
                    function_name,
                    operation_count,
                    estimated_memory_pressure: pressure_score,
                    hotspot_type,
                });
            }
        }
        hotspots.sort_by(|a, b| {
            b.estimated_memory_pressure
                .partial_cmp(&a.estimated_memory_pressure)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        hotspots
    }

    fn identify_optimizations(&self) -> Vec<MemoryOptimization> {
        let mut opts = Vec::new();
        if self
            .module_info
            .memory
            .as_ref()
            .map_or(true, |m| m.maximum.is_none())
        {
            opts.push(MemoryOptimization {
                optimization_type: OptimizationType::SetMemoryLimits,
                description: "Module memory does not have a maximum limit defined.".to_string(),
                estimated_savings: Some(
                    "Improved resource predictability and DOS protection.".to_string(),
                ),
                implementation_difficulty: DifficultyLevel::Easy,
            });
        }

        let total_data_size: u32 = self.module_info.data_segments.iter().map(|d| d.size).sum();
        if total_data_size > 100 * 1024 {
            // Over 100KB in static data
            opts.push(MemoryOptimization {
                optimization_type: OptimizationType::ReduceMemoryFootprint,
                description:
                    "Large total size of data segments. Consider if all data is needed at startup."
                        .to_string(),
                estimated_savings: Some(
                    "Potential size reduction by lazy loading or compressing data.".to_string(),
                ),
                implementation_difficulty: DifficultyLevel::Medium,
            });
        }

        if self
            .allocation_patterns
            .iter()
            .any(|p| matches!(p.pattern_type, AllocationType::FrequentSmallAllocations))
        {
            opts.push(MemoryOptimization {
                optimization_type: OptimizationType::MinimizeAllocations,
                description: "Detected patterns of frequent small memory accesses, potentially indicating inefficient small allocations if custom allocator is used.".to_string(),
                estimated_savings: Some("Performance improvement by using memory pooling or optimizing data structures.".to_string()),
                implementation_difficulty: DifficultyLevel::Hard,
            });
        }
        opts
    }

    fn analyze_memory_safety(&self) -> MemorySafetyAnalysis {
        let mut potential_overflows = Vec::new();
        let mut buffer_safety_score: f64 = 100.0;

        for (func_idx, operations) in &self.memory_operations {
            for op in operations {
                if let Some(offset) = op.offset {
                    // Check against initial memory size if no max. This is a very rough heuristic.
                    let limit = self
                        .module_info
                        .memory
                        .as_ref()
                        .map_or(WASM_PAGE_SIZE_BYTES, |m| {
                            m.maximum.unwrap_or(m.initial) * WASM_PAGE_SIZE_BYTES
                        });

                    let access_size = op.size.unwrap_or(1); // Min 1 byte accessed

                    if offset.saturating_add(access_size) > limit && limit > 0 {
                        // If offset + size > known limit
                        potential_overflows.push(PotentialOverflow {
                            function_index: *func_idx,
                            operation_type: format!("{:?}", op.operation_type),
                            risk_level: RiskLevel::Medium,
                            description: format!("Memory operation at offset {} (size {}) may exceed memory limit {}.", offset, access_size, limit),
                        });
                        buffer_safety_score -= 5.0; // Penalize
                    } else if offset > 1_000_000 && limit == 0 {
                        // Large offset with no memory info
                        potential_overflows.push(PotentialOverflow {
                            function_index: *func_idx,
                            operation_type: format!("{:?}", op.operation_type),
                            risk_level: RiskLevel::Low, // Lower risk as it's less certain
                            description: format!("Memory operation at large offset {} with no explicit memory limits.", offset),
                        });
                        buffer_safety_score -= 1.0;
                    }
                }
            }
        }

        let uses_grow = self
            .allocation_patterns
            .iter()
            .any(|p| matches!(p.pattern_type, AllocationType::DynamicGrowth));
        let has_free_import = self
            .module_info
            .imports
            .iter()
            .any(|imp| imp.name.contains("free"));

        MemorySafetyAnalysis {
            potential_overflows,
            uninitialized_access_risk: if self.module_info.data_segments.is_empty()
                && self.module_info.memory.is_some()
            {
                RiskLevel::Low
            } else {
                RiskLevel::Low
            }, // Hard to detect statically
            memory_leak_risk: if uses_grow && !has_free_import {
                RiskLevel::Medium
            } else {
                RiskLevel::Low
            }, // Very basic heuristic
            buffer_safety_score: buffer_safety_score.max(0.0),
        }
    }
}
