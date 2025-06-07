// ===== graph.rs =====
// src/graph.rs
use crate::types::*;
use anyhow::Result;
use std::collections::{HashMap, HashSet};

pub struct CallGraphBuilder<'a> {
    module_info: &'a ModuleInfo,
    // These fields will be populated from module_info.function_call_instructions
    call_counts: HashMap<u32, u32>, // Key: callee_global_idx, Value: number of times it's called
                                    
}

impl<'a> CallGraphBuilder<'a> {
    pub fn new(module_info: &'a ModuleInfo) -> Self {
        Self {
            module_info,
            call_counts: HashMap::new(),
            // call_edges: Vec::new(), // Not strictly needed if building edges directly
        }
    }

    pub fn build(&mut self) -> Result<CallGraph> {
        // 1. Populate call_counts based on actual parsed calls
        for &(_caller_idx, callee_idx) in &self.module_info.function_call_instructions {
            *self.call_counts.entry(callee_idx).or_insert(0) += 1;
        }

        // 2. Build Nodes (this needs to be robust to include all mentioned functions)
        let nodes = self.build_call_nodes_robust();

        // 3. Build Edges from collected function_call_instructions
        let edges = self.build_call_edges_from_parsed_instructions();

        // 4. Find Entry Points
        let entry_points = self.find_entry_points();

        // 5. Find Unreachable Functions using the new accurate graph data
        let unreachable_functions = self.find_unreachable_functions(&nodes, &edges, &entry_points);

        // Debugging output
        println!(
            "[DEBUG CallGraphBuilder] Final Nodes Count: {}",
            nodes.len()
        );
        println!(
            "[DEBUG CallGraphBuilder] Final Edges Count: {}",
            edges.len()
        );
        if edges.is_empty() && !self.module_info.function_call_instructions.is_empty() {
            println!("[DEBUG CallGraphBuilder] WARNING: Had call instructions but produced 0 edges. Check build_call_edges_from_parsed_instructions logic.");
        } else if edges.is_empty() && self.module_info.function_call_instructions.is_empty() {
            println!("[DEBUG CallGraphBuilder] INFO: No call instructions found in module_info, so 0 edges is expected.");
        }

        Ok(CallGraph {
            nodes,
            edges,
            entry_points,
            unreachable_functions,
        })
    }

    // More robust node building
    fn build_call_nodes_robust(&self) -> Vec<CallNode> {
        let mut node_map: HashMap<u32, CallNode> = HashMap::new();
        let mut max_seen_idx: u32 = 0;

        // Add defined functions
        for func in &self.module_info.functions {
            max_seen_idx = max_seen_idx.max(func.index);
            node_map.insert(
                func.index,
                CallNode {
                    function_index: func.index,
                    name: func.name.clone(),
                    is_imported: func.is_imported, // Should be false
                    is_exported: func.is_exported,
                    call_count: self.call_counts.get(&func.index).copied().unwrap_or(0),
                },
            );
        }

        // Add imported functions
        let mut current_imported_func_global_idx = 0;
        for import in &self.module_info.imports {
            if let ImportKind::Function { .. } = import.kind {
                max_seen_idx = max_seen_idx.max(current_imported_func_global_idx);
                // Ensure not to overwrite if a defined function somehow has an index clashing with an import's assumed global index
                node_map
                    .entry(current_imported_func_global_idx)
                    .or_insert_with(|| CallNode {
                        function_index: current_imported_func_global_idx,
                        name: Some(format!("{}::{} (import)", import.module, import.name)),
                        is_imported: true,
                        is_exported: false, // Imports are not directly exported from the module itself in this context
                        call_count: self
                            .call_counts
                            .get(&current_imported_func_global_idx)
                            .copied()
                            .unwrap_or(0),
                    });
                current_imported_func_global_idx += 1;
            }
        }

        // Ensure all functions mentioned in calls (even if not explicitly defined/imported earlier, e.g. if parsing is partial)
        // and exports have nodes.
        for &(caller_idx, callee_idx) in &self.module_info.function_call_instructions {
            max_seen_idx = max_seen_idx.max(caller_idx);
            max_seen_idx = max_seen_idx.max(callee_idx);
            node_map.entry(caller_idx).or_insert_with(|| CallNode {
                function_index: caller_idx,
                name: Some(format!("func_{} (implicit_caller)", caller_idx)),
                is_imported: caller_idx < current_imported_func_global_idx, // Heuristic: lower indices are often imports
                is_exported: false, // Cannot know without iterating exports
                call_count: self.call_counts.get(&caller_idx).copied().unwrap_or(0),
            });
            node_map.entry(callee_idx).or_insert_with(|| CallNode {
                function_index: callee_idx,
                name: Some(format!("func_{} (implicit_callee)", callee_idx)),
                is_imported: callee_idx < current_imported_func_global_idx, // Heuristic
                is_exported: false,
                call_count: self.call_counts.get(&callee_idx).copied().unwrap_or(0),
            });
        }

        for export in &self.module_info.exports {
            if export.kind == ExportKind::Function {
                max_seen_idx = max_seen_idx.max(export.index);
                let node_entry = node_map.entry(export.index).or_insert_with(|| CallNode {
                    function_index: export.index,
                    name: Some(export.name.clone()), // Use export name if no other name yet
                    is_imported: export.index < current_imported_func_global_idx, // Heuristic
                    is_exported: true,
                    call_count: self.call_counts.get(&export.index).copied().unwrap_or(0),
                });
                node_entry.is_exported = true; // Ensure export flag is set
                if node_entry.name.is_none() {
                    node_entry.name = Some(export.name.clone());
                }
            }
        }
        if let Some(start_func_idx) = self.module_info.start_function {
            node_map.entry(start_func_idx).or_insert_with(|| CallNode {
                function_index: start_func_idx,
                name: Some(format!("_start (func_{})", start_func_idx)),
                is_imported: start_func_idx < current_imported_func_global_idx, // Heuristic
                is_exported: false, // Start function usually not an export by name
                call_count: self.call_counts.get(&start_func_idx).copied().unwrap_or(0),
            });
        }

        // Convert map to Vec and sort by function_index for consistent output
        let mut nodes_vec: Vec<CallNode> = node_map.into_values().collect();
        nodes_vec.sort_by_key(|n| n.function_index);

        // Fill any gaps up to max_seen_idx if strict contiguous indexing is desired by D3.
        // However, D3 typically handles sparse node IDs if links reference them correctly.
        // For simplicity now, we'll just return the nodes we've positively identified.

        nodes_vec
    }

    // This method now correctly uses the parsed call instructions.
    fn build_call_edges_from_parsed_instructions(&self) -> Vec<CallEdge> {
        let mut edge_map: HashMap<(u32, u32), u32> = HashMap::new();

        for &(caller_idx, callee_idx) in &self.module_info.function_call_instructions {
            *edge_map.entry((caller_idx, callee_idx)).or_insert(0) += 1;
        }

        edge_map
            .into_iter()
            .map(|((from, to), count)| CallEdge {
                from,
                to,
                call_sites: count, // count is the number of call instructions from 'from' to 'to'
            })
            .collect()
    }

    fn find_entry_points(&self) -> Vec<u32> {
        let mut entry_points = HashSet::new(); // Use HashSet to avoid duplicates initially

        if let Some(start_func_global_idx) = self.module_info.start_function {
            entry_points.insert(start_func_global_idx);
        }

        for export in &self.module_info.exports {
            if export.kind == ExportKind::Function {
                // export.index is the global function index
                entry_points.insert(export.index);
            }
        }

        let mut sorted_entry_points: Vec<u32> = entry_points.into_iter().collect();
        sorted_entry_points.sort_unstable();

        // Fallback: If no explicit entry points, consider the first non-imported *defined* function
        if sorted_entry_points.is_empty() && !self.module_info.functions.is_empty() {
            if let Some(func) = self.module_info.functions.iter().find(|f| !f.is_imported) {
                sorted_entry_points.push(func.index); // func.index is global index
            }
        }
        sorted_entry_points
    }

    fn find_unreachable_functions(
        &self,
        nodes: &[CallNode],
        edges: &[CallEdge],
        entry_points: &[u32],
    ) -> Vec<u32> {
        let mut reachable = HashSet::new();
        let mut to_visit = Vec::new();

        // All imported functions are considered reachable from an external perspective
        for node in nodes {
            if node.is_imported {
                reachable.insert(node.function_index);
            }
        }

        // Start with explicitly defined entry points
        for &ep_idx in entry_points {
            if !reachable.contains(&ep_idx) {
                // Avoid re-adding if an entry point is also an import (unlikely but possible)
                to_visit.push(ep_idx);
            }
        }
        to_visit.sort_unstable();
        to_visit.dedup();

        let mut adj: HashMap<u32, Vec<u32>> = HashMap::new();
        for edge in edges {
            adj.entry(edge.from).or_default().push(edge.to);
        }

        while let Some(func_idx) = to_visit.pop() {
            if reachable.insert(func_idx) {
                // If it wasn't already reachable
                if let Some(callees) = adj.get(&func_idx) {
                    for &callee_idx in callees {
                        if !reachable.contains(&callee_idx) {
                            to_visit.push(callee_idx);
                        }
                    }
                }
            }
        }

        nodes
            .iter()
            .filter_map(|node| {
                // A function is considered dead code if it's defined in the module (not imported)
                // AND it's not found in the reachable set.
                if !node.is_imported && !reachable.contains(&node.function_index) {
                    Some(node.function_index)
                } else {
                    None
                }
            })
            .collect()
    }
}
