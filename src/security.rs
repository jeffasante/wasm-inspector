
// ===== security.rs =====
use crate::types::*;
use anyhow::Result;
use std::collections::HashSet;

pub struct SecurityAnalyzer<'a> {
    module_info: &'a ModuleInfo,
}

impl<'a> SecurityAnalyzer<'a> {
    pub fn new(module_info: &'a ModuleInfo) -> Self {
        Self { module_info }
    }

    pub fn analyze(&self) -> Result<SecurityAnalysis> {
        let capabilities = self.detect_capabilities();
        let vulnerabilities = self.detect_vulnerabilities();
        let sandbox_compatibility = self.assess_sandbox_compatibility();
        let wasi_usage = self.analyze_wasi_usage();

        Ok(SecurityAnalysis {
            capabilities,
            vulnerabilities,
            sandbox_compatibility,
            wasi_usage,
        })
    }

    fn has_filesystem_access(&self, imports: &HashSet<(&String, &String)>) -> bool {
        imports.iter().any(|(_, name)| {
            name.contains("fd_")
                || name.contains("path_")
                || name.contains("file")
                || name.contains("dir")
        })
    }

    fn detect_capabilities(&self) -> Vec<Capability> {
        let mut capabilities = Vec::new();
        let imports: HashSet<_> = self
            .module_info
            .imports
            .iter()
            .map(|i| (&i.module, &i.name))
            .collect();

        // File system access
        if self.has_filesystem_access(&imports) {
            capabilities.push(Capability {
                name: "File System Access".to_string(),
                description: "Module can read/write files and directories".to_string(),
                risk_level: RiskLevel::High,
                evidence: self.collect_filesystem_evidence(),
            });
        }

        // Network access
        if imports.iter().any(|(_, name)| {
            name.contains("sock_")
                || name.contains("poll_")
                || name.contains("network")
                || name.contains("tcp")
                || name.contains("udp")
        }) {
            capabilities.push(Capability {
                name: "Network Access".to_string(),
                description: "Module can make network connections".to_string(),
                risk_level: RiskLevel::High,
                evidence: self.collect_network_evidence(),
            });
        }

        // Process/system access
        if imports.iter().any(|(_, name)| {
            name.contains("proc_")
                || name.contains("environ")
                || name.contains("exit")
                || name.contains("signal")
        }) {
            capabilities.push(Capability {
                name: "System Access".to_string(),
                description: "Module can access system resources and processes".to_string(),
                risk_level: RiskLevel::Medium,
                evidence: self.collect_system_evidence(),
            });
        }

        // Clock/time access
        if imports
            .iter()
            .any(|(_, name)| name.contains("clock_") || name.contains("time"))
        {
            capabilities.push(Capability {
                name: "Time Access".to_string(),
                description: "Module can access system time".to_string(),
                risk_level: RiskLevel::Low,
                evidence: self.collect_time_evidence(),
            });
        }

        // Random number generation
        if imports
            .iter()
            .any(|(_, name)| name.contains("random") || name.contains("rand"))
        {
            capabilities.push(Capability {
                name: "Random Generation".to_string(),
                description: "Module can generate random numbers".to_string(),
                risk_level: RiskLevel::Low,
                evidence: self.collect_random_evidence(),
            });
        }

        // Memory allocation
        if imports.iter().any(|(_, name)| {
            name.contains("malloc")
                || name.contains("free")
                || name.contains("alloc")
                || name.contains("realloc")
        }) || self.module_info.imports.iter().any(|i| i.name == "memory.grow" && i.module == "env") { // Also check for direct memory.grow import
            capabilities.push(Capability {
                name: "Dynamic Memory".to_string(),
                description: "Module performs dynamic memory allocation or growth".to_string(),
                risk_level: RiskLevel::Medium,
                evidence: self.collect_memory_evidence(),
            });
        }


        // Crypto operations
        if imports.iter().any(|(_, name)| {
            name.contains("crypto")
                || name.contains("hash")
                || name.contains("encrypt")
                || name.contains("decrypt")
                || name.contains("sign")
                || name.contains("verify")
        }) {
            capabilities.push(Capability {
                name: "Cryptographic Operations".to_string(),
                description: "Module performs cryptographic operations".to_string(),
                risk_level: RiskLevel::Medium,
                evidence: self.collect_crypto_evidence(),
            });
        }

        capabilities
    }

    fn detect_vulnerabilities(&self) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check for unbounded memory growth
        if let Some(ref memory) = self.module_info.memory {
            if memory.maximum.is_none() {
                vulnerabilities.push(Vulnerability {
                    id: "UNBOUNDED_MEMORY".to_string(),
                    description: "Memory has no maximum limit - potential for memory exhaustion"
                        .to_string(),
                    severity: RiskLevel::Medium,
                    location: "Memory section".to_string(),
                });
            }
        }

        // Check for large number of imports (potential attack surface)
        if self.module_info.imports.len() > 50 {
            vulnerabilities.push(Vulnerability {
                id: "LARGE_IMPORT_SURFACE".to_string(),
                description: format!(
                    "Module imports {} functions - large attack surface",
                    self.module_info.imports.len()
                ),
                severity: RiskLevel::Medium,
                location: "Import section".to_string(),
            });
        }

        // Check for suspicious function names
        let suspicious_names = ["eval", "exec", "system", "shell", "cmd", "invoke"];
        for import in &self.module_info.imports {
            if suspicious_names
                .iter()
                .any(|&sus| import.name.to_lowercase().contains(sus))
            {
                vulnerabilities.push(Vulnerability {
                    id: "SUSPICIOUS_IMPORT".to_string(),
                    description: format!("Suspicious import function: {}", import.name),
                    severity: RiskLevel::High,
                    location: format!("Import: {}::{}", import.module, import.name),
                });
            }
        }

        // Check for potential buffer overflow patterns (unsafe C imports)
        if self.module_info.imports.iter().any(|i| {
            (i.module == "env" || i.module.is_empty()) && // Common for C stdlib
            (i.name.contains("strcpy") // Classic unsafe
                || i.name.contains("sprintf") // Classic unsafe
                || i.name.contains("gets")    // Classic unsafe
                || i.name.contains("strcat")) // Classic unsafe
        }) {
            vulnerabilities.push(Vulnerability {
                id: "UNSAFE_C_STRING_OPS".to_string(),
                description: "Imports C standard library functions known for buffer overflow vulnerabilities (e.g., strcpy, sprintf).".to_string(),
                severity: RiskLevel::High,
                location: "Import section (check 'env' imports)".to_string(),
            });
        }

        vulnerabilities
    }

    fn assess_sandbox_compatibility(&self) -> SandboxCompatibility {
        let mut restrictions = Vec::new();
        let mut browser_safe = true;
        let node_safe = true; // Node.js is generally more permissive with WASI
        let mut cloudflare_workers_safe = true;

        let uses_wasi = self.module_info.imports.iter().any(|i| i.module.starts_with("wasi"));

        if uses_wasi {
            // WASI is problematic for browsers without polyfills
            // browser_safe = false; // Let's not mark it unsafe just for WASI, polyfills exist
            restrictions.push("WASI imports may require polyfills or specific runtime support (e.g., browser, Node.js).".to_string());
        }
        
        // Stricter check for Cloudflare workers regarding WASI
        if self.module_info.imports.iter().any(|i| i.module.starts_with("wasi_snapshot") || i.module.starts_with("wasi_unstable")) {
            cloudflare_workers_safe = false;
            restrictions.push("Direct WASI snapshot/unstable imports are generally not supported in Cloudflare Workers.".to_string());
        }


        // Check for file system access specifically
        if self.module_info.imports.iter().any(|i| i.name.contains("fd_") || i.name.contains("path_")) {
            browser_safe = false; // FS access is a strong signal against browser safety without specific APIs
            // cloudflare_workers_safe = false; // Already covered if WASI is the provider
            restrictions.push("Direct file system access (fd_*, path_*) not available in standard browser sandbox or typical edge runtimes without specific capabilities.".to_string());
        }

        // Check memory limits
        if let Some(ref memory) = self.module_info.memory {
            if memory.initial > (128 * 1024 * 1024) / (64 * 1024) { // e.g. > 128MB (initial pages for 128MB)
                 // Cloudflare Workers has a limit like 128MB RAM for the isolate.
                 // This calculation is pages: 128MB / 64KB/page = 2048 pages.
                if memory.initial > 2000 { // Check against a reasonable page limit for edge
                    cloudflare_workers_safe = false;
                    restrictions.push(format!("High initial memory ({}) may exceed edge runtime limits (e.g., Cloudflare Workers).", memory.initial * 64));
                }
            }
        } else { // No memory section defined
            cloudflare_workers_safe = false; // Usually an issue for non-trivial workers
            restrictions.push("No memory section defined; Cloudflare Workers typically require one for non-trivial modules.".to_string());
        }


        // Check module size (rough estimate)
        let estimated_size = self.estimate_module_size();
        if estimated_size > 1_000_000 { // 1MB for compiled WASM
            cloudflare_workers_safe = false;
            restrictions.push(format!("Module size (approx. {} bytes) may exceed edge runtime limits (e.g., Cloudflare Workers 1MB compressed limit).", estimated_size));
        }

        SandboxCompatibility {
            browser_safe,
            node_safe,
            cloudflare_workers_safe,
            restrictions,
        }
    }

    fn analyze_wasi_usage(&self) -> WasiUsage {
        let wasi_imports: Vec<_> = self
            .module_info
            .imports
            .iter()
            .filter(|i| i.module.starts_with("wasi_snapshot") || i.module.starts_with("wasi_unstable")) // More specific
            .collect();

        if wasi_imports.is_empty() {
            return WasiUsage {
                uses_wasi: false,
                wasi_version: None,
                required_capabilities: Vec::new(),
            };
        }

        let wasi_version = if wasi_imports.iter().any(|i| i.module == "wasi_snapshot_preview1") {
            Some("Preview 1".to_string())
        } else if wasi_imports.iter().any(|i| i.module.contains("preview2")) { // Future-proofing
            Some("Preview 2".to_string())
        } else if wasi_imports.iter().any(|i| i.module == "wasi_unstable") {
             Some("Unstable (Legacy Preview 0/Pre-Preview 1)".to_string())
        }else {
            Some("Unknown WASI version".to_string())
        };

        let mut capabilities = HashSet::new();
        for import in &wasi_imports {
            // Simplified mapping based on common prefixes from WASI Preview 1
            if import.name.starts_with("fd_") { capabilities.insert("file-system"); }
            else if import.name.starts_with("path_") { capabilities.insert("file-system-paths"); }
            else if import.name.starts_with("sock_") { capabilities.insert("sockets"); }
            else if import.name.starts_with("proc_") { capabilities.insert("process-control"); }
            else if import.name.starts_with("environ_") { capabilities.insert("environment-variables"); }
            else if import.name.starts_with("clock_") { capabilities.insert("clocks"); }
            else if import.name.starts_with("random_") { capabilities.insert("randomness"); }
            else if import.name == "sched_yield" { capabilities.insert("scheduler");}
            // args_get, args_sizes_get -> command-line-arguments
            // poll_oneoff -> polling
        }

        WasiUsage {
            uses_wasi: true,
            wasi_version,
            required_capabilities: capabilities.into_iter().map(String::from).collect(),
        }
    }

    fn collect_filesystem_evidence(&self) -> Vec<String> {
        self.module_info
            .imports
            .iter()
            .filter(|i| {
                i.name.contains("fd_") || i.name.contains("path_") || i.name.contains("file")
            })
            .map(|i| format!("{}::{}", i.module, i.name))
            .take(5) // Limit evidence
            .collect()
    }

    fn collect_network_evidence(&self) -> Vec<String> {
        self.module_info
            .imports
            .iter()
            .filter(|i| {
                i.name.contains("sock_") || i.name.contains("poll_") || i.name.contains("network")
            })
            .map(|i| format!("{}::{}", i.module, i.name))
            .take(5)
            .collect()
    }

    fn collect_system_evidence(&self) -> Vec<String> {
        self.module_info
            .imports
            .iter()
            .filter(|i| {
                i.name.contains("proc_") || i.name.contains("environ") || i.name.contains("exit")
            })
            .map(|i| format!("{}::{}", i.module, i.name))
            .take(5)
            .collect()
    }

    fn collect_time_evidence(&self) -> Vec<String> {
        self.module_info
            .imports
            .iter()
            .filter(|i| i.name.contains("clock_") || i.name.contains("time"))
            .map(|i| format!("{}::{}", i.module, i.name))
            .take(5)
            .collect()
    }

    fn collect_random_evidence(&self) -> Vec<String> {
        self.module_info
            .imports
            .iter()
            .filter(|i| i.name.contains("random") || i.name.contains("rand"))
            .map(|i| format!("{}::{}", i.module, i.name))
            .take(5)
            .collect()
    }

    fn collect_memory_evidence(&self) -> Vec<String> {
        self.module_info
            .imports
            .iter()
            .filter(|i| {
                i.name.contains("malloc") || i.name.contains("free") || i.name.contains("alloc") || (i.name == "memory.grow" && i.module == "env")
            })
            .map(|i| format!("{}::{}", i.module, i.name))
            .take(5)
            .collect()
    }

    fn collect_crypto_evidence(&self) -> Vec<String> {
        self.module_info
            .imports
            .iter()
            .filter(|i| {
                let name_lower = i.name.to_lowercase();
                name_lower.contains("crypto")
                    || name_lower.contains("hash")
                    || name_lower.contains("encrypt")
                    || name_lower.contains("decrypt")
                    || name_lower.contains("sign")
                    || name_lower.contains("verify")
            })
            .map(|i| format!("{}::{}", i.module, i.name))
            .take(5)
            .collect()
    }

    fn estimate_module_size(&self) -> u32 {
        let mut size = 0u32;
        size += self.module_info.functions.iter().map(|f| f.body_size).sum::<u32>();
        size += self.module_info.data_segments.iter().map(|d| d.size).sum::<u32>();
        size += self.module_info.custom_sections.iter().map(|c| c.size).sum::<u32>();
        size += (self.module_info.imports.len() * 32) as u32; // Rough estimates
        size += (self.module_info.exports.len() * 24) as u32;
        size += (self.module_info.globals.len() * 16) as u32;
        size += (self.module_info.type_signatures.len() * 10) as u32; // Rough estimate for type section
        size += 1000; // General overhead for other sections
        size
    }
}

