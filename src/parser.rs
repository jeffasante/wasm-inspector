
// ===== parser.rs =====
// src/parser.rs
use crate::types::*;
use anyhow::{Result};
use std::collections::HashMap;
use wasmparser::{
    DataSectionReader, ElementSectionReader, ExportSectionReader, FunctionSectionReader,
    GlobalSectionReader, ImportSectionReader, MemorySectionReader, Parser, Payload,
    TableSectionReader, TypeSectionReader, Operator,
};
 

pub struct WasmParser<'a> {
    bytes: &'a [u8],
    module_info: ModuleInfo,
    type_signatures: Vec<wasmparser::FuncType>, // Keep for parsing
    function_names: HashMap<u32, String>, // Key is global function index
    imported_function_count: u32, // Added field
}




impl<'a> WasmParser<'a> {
    pub fn new(bytes: &'a [u8]) -> Result<Self> {
        Ok(Self {
            bytes,
            module_info: ModuleInfo {
                version: 0,
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
                function_call_instructions: Vec::new(),
                type_signatures: Vec::new(), // Initialize as empty Vec<String>
            },
            type_signatures: Vec::new(), // This is Vec<wasmparser::FuncType>
            function_names: HashMap::new(),
            imported_function_count: 0, // Initialize
        })
    }

    pub fn parse(mut self) -> Result<ModuleInfo> {
        let parser = Parser::new(0);
        let mut defined_function_idx_counter: u32 = 0;

        // Pre-calculate imported function count as it's needed for global indexing early
        // This requires a preliminary pass or careful ordering.
        // For simplicity, we'll parse imports first, then use the count.
        // A full parser might do multiple passes or collect sections first.
        // Let's parse imports first to get this count.
        
        let mut payloads = Vec::new();
        for payload_result in parser.parse_all(self.bytes) {
            payloads.push(payload_result?);
        }

        // First pass for imports to count imported functions
        for payload in &payloads {
            if let Payload::ImportSection(reader) = payload {
                let temp_reader = reader.clone(); // Clone to iterate
                 for import_result in temp_reader {
                    let import = import_result?;
                    if matches!(import.ty, wasmparser::TypeRef::Func(_)) {
                        self.imported_function_count += 1;
                    }
                }
            }
        }


        for payload in payloads { // Iterate over collected payloads
            match payload {
                Payload::Version { num, .. } => {
                    self.module_info.version = num as u32;
                }
                Payload::TypeSection(reader) => {
                    self.parse_type_section(reader)?;
                }
                Payload::ImportSection(reader) => {
                    self.parse_import_section(reader)?;
                }
                Payload::FunctionSection(reader) => {
                    self.parse_function_section(reader)?;
                }
                Payload::TableSection(reader) => {
                    self.parse_table_section(reader)?;
                }
                Payload::MemorySection(reader) => {
                    self.parse_memory_section(reader)?;
                }
                Payload::GlobalSection(reader) => {
                    self.parse_global_section(reader)?;
                }
                Payload::ExportSection(reader) => {
                    self.parse_export_section(reader)?;
                }
                Payload::StartSection { func, .. } => {
                    self.module_info.start_function = Some(func); // func is already global index
                }
                Payload::ElementSection(reader) => {
                    self.parse_element_section(reader)?;
                }
                Payload::DataSection(reader) => {
                    self.parse_data_section(reader)?;
                }
                Payload::CodeSectionStart { .. } => {
                    // Handled by CodeSectionEntry
                }
                Payload::CodeSectionEntry(body) => {
                    // defined_function_idx_counter is the index within defined functions (0 to N-1)
                    let current_func_global_idx = self.imported_function_count + defined_function_idx_counter;
                    self.parse_function_body_and_calls(current_func_global_idx, defined_function_idx_counter, body)?;
                    defined_function_idx_counter += 1;
                }
                Payload::CustomSection(reader) => {
                    self.parse_custom_section(reader)?;
                }
                _ => {
                    // Skip other sections for now
                }
            }
        }

        // Update function metadata after parsing all sections
        self.update_function_metadata();

        Ok(self.module_info)
    }

       fn parse_type_section(&mut self, reader: TypeSectionReader) -> Result<()> {
        for result_rec_group in reader {
            let rec_group = result_rec_group?; 
            for sub_type in rec_group.types() {
                if let wasmparser::CompositeType::Func(func_type) = &sub_type.composite_type {
                    self.type_signatures.push(func_type.clone());
                }
            }
        }
        Ok(())
    }

    fn parse_import_section(&mut self, reader: ImportSectionReader) -> Result<()> {
        // `self.imported_function_count` is already set.
        // This loop populates `self.module_info.imports`.
        // The `index` field of `Import` struct is its index within the import array.
        let mut _current_func_import_idx: i32 = 0;
        for (idx, import_result) in reader.into_iter().enumerate() {
            let import = import_result?;
            let kind = match import.ty {
                wasmparser::TypeRef::Func(type_index) => {
                    // let global_func_idx = _current_func_import_idx; // This is the global index for this imported function
                    _current_func_import_idx += 1;
                    ImportKind::Function { type_index } // Store type_index, global_func_idx handled by position
                }
                wasmparser::TypeRef::Table(table_type) => ImportKind::Table {
                    table_type: TableType {
                        element_type: format!("{:?}", table_type.element_type),
                        initial: table_type.initial,
                        maximum: table_type.maximum,
                    },
                },
                wasmparser::TypeRef::Memory(memory_type) => ImportKind::Memory {
                    memory_type: MemoryType {
                        initial: memory_type.initial as u32,
                        maximum: memory_type.maximum.map(|m| m as u32),
                        shared: memory_type.shared,
                    },
                },
                wasmparser::TypeRef::Global(global_type) => ImportKind::Global {
                    global_type: GlobalType {
                        value_type: format!("{:?}", global_type.content_type),
                        mutable: global_type.mutable,
                    },
                },
                _ => continue, // Other import types like Tag
            };

            self.module_info.imports.push(Import {
                module: import.module.to_string(),
                name: import.name.to_string(),
                kind,
                index: idx as u32, // Index within the import section itself
            });
        }
        Ok(())
    }

    fn parse_function_section(&mut self, reader: FunctionSectionReader) -> Result<()> {
        // `self.module_info.functions` stores only defined functions.
        // Their global index = imported_function_count + their index in this section.
        for (defined_idx, type_index_result) in reader.into_iter().enumerate() {
            let type_index = type_index_result?;
            let global_function_index = self.imported_function_count + defined_idx as u32;
            self.module_info.functions.push(Function {
                index: global_function_index, // Store global index
                type_index,
                locals: Vec::new(),
                body_size: 0, // Will be set in CodeSectionEntry
                is_imported: false, // These are defined functions
                is_exported: false, // Will be set later
                name: None,         // Will be set later
            });
        }
        Ok(())
    }

    fn parse_table_section(&mut self, reader: TableSectionReader) -> Result<()> {
        for (index, table) in reader.into_iter().enumerate() {
            let table = table?;
            self.module_info.tables.push(Table {
                index: index as u32,
                table_type: TableType {
                    element_type: format!("{:?}", table.ty.element_type),
                    initial: table.ty.initial,
                    maximum: table.ty.maximum,
                },
                is_imported: false,
                is_exported: false,
            });
        }
        Ok(())
    }

    fn parse_memory_section(&mut self, reader: MemorySectionReader) -> Result<()> {
        for memory in reader {
            let memory = memory?;
            self.module_info.memory = Some(Memory {
                initial: memory.initial as u32,
                maximum: memory.maximum.map(|m| m as u32),
                shared: memory.shared,
                is_imported: false,
                is_exported: false,
            });
            break; 
        }
        Ok(())
    }

    fn parse_global_section(&mut self, reader: GlobalSectionReader) -> Result<()> {
        for (index, global) in reader.into_iter().enumerate() {
            let global = global?;
            self.module_info.globals.push(Global {
                index: index as u32,
                global_type: GlobalType {
                    value_type: format!("{:?}", global.ty.content_type),
                    mutable: global.ty.mutable,
                },
                init_value: None, 
                is_imported: false,
                is_exported: false,
            });
        }
        Ok(())
    }

    fn parse_export_section(&mut self, reader: ExportSectionReader) -> Result<()> {
        for export_result in reader {
            let export = export_result?;
            let kind = match export.kind {
                wasmparser::ExternalKind::Func => ExportKind::Function,
                wasmparser::ExternalKind::Table => ExportKind::Table,
                wasmparser::ExternalKind::Memory => ExportKind::Memory,
                wasmparser::ExternalKind::Global => ExportKind::Global,
                _ => continue, // Other export kinds like Tag
            };
            // export.index is the global index of the exported item (e.g. global func index)
            self.module_info.exports.push(Export {
                name: export.name.to_string(),
                kind,
                index: export.index, 
            });
        }
        Ok(())
    }

    fn parse_element_section(&mut self, reader: ElementSectionReader) -> Result<()> {
        for (index, result_element) in reader.into_iter().enumerate() {
            let element = result_element?;
            let element_count = match &element.items {
                wasmparser::ElementItems::Functions(reader) => reader.clone().count() as u32,
                wasmparser::ElementItems::Expressions(_ref_type, reader) => reader.clone().count() as u32,
            };

            let (final_table_index, final_offset) = match element.kind {
                wasmparser::ElementKind::Active { table_index, offset_expr} => {
                    let resolved_table_index = table_index.unwrap_or(0);
                    let mut ops_reader = offset_expr.get_operators_reader();
                    let offset_val = match ops_reader.read()? {
                        wasmparser::Operator::I32Const { value } => {
                            match ops_reader.read()? {
                                wasmparser::Operator::End => { ops_reader.ensure_end()?; Some(value as u32) }
                                _ => None 
                            }
                        }
                        _ => None,
                    };
                    (Some(resolved_table_index), offset_val)
                }
                wasmparser::ElementKind::Passive | wasmparser::ElementKind::Declared => (None, None),
            };
            let is_passive = !matches!(element.kind, wasmparser::ElementKind::Active { .. });
            self.module_info.element_segments.push(ElementSegment {
                index: index as u32,
                table_index: final_table_index,
                offset: final_offset,
                element_count,
                is_passive,
            });
        }
        Ok(())
    }

    fn parse_data_section(&mut self, reader: DataSectionReader) -> Result<()> {
        for (index, data_result) in reader.into_iter().enumerate() {
            let data = data_result?;
            let (memory_index, offset_val) = match data.kind {
                 wasmparser::DataKind::Active { memory_index, offset_expr } => {
                    let mut ops_reader = offset_expr.get_operators_reader();
                    let offset_val = match ops_reader.read()? {
                        wasmparser::Operator::I32Const { value } => {
                             match ops_reader.read()? {
                                wasmparser::Operator::End => { ops_reader.ensure_end()?; Some(value as u32) }
                                _ => None
                            }
                        }
                         _ => None,
                    };
                    (memory_index, offset_val.unwrap_or(0)) // Default offset 0 if expr complex
                 }
                 wasmparser::DataKind::Passive => (0,0), // Passive has no mem_idx/offset here
            };

            self.module_info.data_segments.push(DataSegment {
                index: index as u32,
                memory_index, // memory_index from DataKind
                offset: offset_val, // offset from DataKind
                size: data.data.len() as u32,
                is_passive: matches!(data.kind, wasmparser::DataKind::Passive),
            });
        }
        Ok(())
    }

    fn parse_function_body_and_calls(&mut self, current_func_global_idx: u32, defined_func_idx: u32, body: wasmparser::FunctionBody) -> Result<()> {
        let locals_reader = body.get_locals_reader()?;
        let mut locals_for_func = Vec::new();
        for local_result in locals_reader {
            let (count, value_type) = local_result?;
            locals_for_func.push(LocalType {
                count,
                value_type: format!("{:?}", value_type),
            });
        }

        // Update the corresponding Function struct for defined functions
        if let Some(func) = self.module_info.functions.get_mut(defined_func_idx as usize) {
            func.locals = locals_for_func;
            // The body_size includes locals + operators.
            // body.range() gives the range of the function body (code) in the original byte stream.
            // For body_size as just code, it's body.range().end - operators_offset.
            // For now, use the full size from code section entry.
            let operators_offset = body.get_operators_reader()?.original_position();
            func.body_size = (body.range().end - operators_offset) as u32;

        } else {
            // This should not happen if defined_func_idx is correct.
            anyhow::bail!("Function at defined index {} not found when parsing body.", defined_func_idx);
        }

        // Parse operators for calls
        let mut ops_reader = body.get_operators_reader()?;
        while !ops_reader.eof() {
            let operator = ops_reader.read()?;
            match operator {
                Operator::Call { function_index } => {
                    // function_index is the global index of the callee
                    self.module_info.function_call_instructions.push((current_func_global_idx, function_index));
                }
                // TODO: Handle Operator::CallIndirect if needed for more detailed graph
                _ => {}
            }
        }
        Ok(())
    }


    fn parse_custom_section(&mut self, reader: wasmparser::CustomSectionReader) -> Result<()> {
        let name = reader.name().to_string();
        let data = reader.data();
        let size = data.len() as u32;

        if name == "name" {
            self.parse_name_section(data)?;
        }

        self.module_info
            .custom_sections
            .push(CustomSection { name, size });
        Ok(())
    }

    fn parse_name_section(&mut self, data: &[u8]) -> Result<()> {
        let name_reader = wasmparser::NameSectionReader::new(data, 0);
        for subsection_result in name_reader {
            match subsection_result? {
                wasmparser::Name::Function(names) => {
                    for name_map_entry in names {
                        let naming = name_map_entry?;
                        // naming.index is the global function index
                        self.function_names.insert(naming.index, naming.name.to_string());
                    }
                }
                // TODO: Parse other name subsections if needed (module, locals, etc.)
                _ => {}
            }
        }
        Ok(())
    }

    fn update_function_metadata(&mut self) {
        // is_imported is set during Function struct creation.
        // For defined functions:
        for func_info in self.module_info.functions.iter_mut() {
            // Check if exported
            if self.module_info.exports.iter().any(|exp| exp.kind == ExportKind::Function && exp.index == func_info.index) {
                func_info.is_exported = true;
            }
            // Assign name from name section or export
            if let Some(name_from_section) = self.function_names.get(&func_info.index) {
                func_info.name = Some(name_from_section.clone());
            } else if func_info.is_exported {
                // If no name from "name" section, use export name
                if let Some(export) = self.module_info.exports.iter().find(|exp| exp.kind == ExportKind::Function && exp.index == func_info.index) {
                     func_info.name = Some(export.name.clone());
                }
            }
        }
        
        // Update export status for memory, tables, globals
        if let Some(ref mut memory) = self.module_info.memory {
            // Memory index is always 0 for current WASM
            if self.module_info.exports.iter().any(|exp| exp.kind == ExportKind::Memory && exp.index == 0) {
                memory.is_exported = true;
            }
        }
        for table_info in self.module_info.tables.iter_mut() {
            if self.module_info.exports.iter().any(|exp| exp.kind == ExportKind::Table && exp.index == table_info.index) {
                table_info.is_exported = true;
            }
        }
        for global_info in self.module_info.globals.iter_mut() {
            if self.module_info.exports.iter().any(|exp| exp.kind == ExportKind::Global && exp.index == global_info.index) {
                global_info.is_exported = true;
            }
        }
        // TODO: Update is_imported for tables, memory, globals based on import section analysis.
    }
}
