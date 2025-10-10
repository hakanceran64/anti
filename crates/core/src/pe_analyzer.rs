use crate::{Result, heuristic::*};
use std::path::Path;
use std::collections::HashMap;
pub struct AdvancedPEAnalyzer {
    suspicious_imports: HashMap<String, Vec<SuspiciousImport>>,
    packer_signatures: Vec<PackerSignature>,
}
#[derive(Debug, Clone)]
pub struct SuspiciousImport {
    pub dll: String,
    pub function: String,
    pub risk_level: u8,
    pub description: String,
    pub category: String,
}
#[derive(Debug, Clone)]
pub struct PackerSignature {
    pub name: String,
    pub signature: Vec<u8>,
    pub offset: usize,
    pub section_name: Option<String>,
}
impl AdvancedPEAnalyzer {
    pub fn new() -> Self {
        Self {
            suspicious_imports: Self::load_suspicious_imports(),
            packer_signatures: Self::load_packer_signatures(),
        }
    }
    fn load_suspicious_imports() -> HashMap<String, Vec<SuspiciousImport>> {
        let mut imports = HashMap::new();
        imports.insert("kernel32.dll".to_string(), vec![
            SuspiciousImport {
                dll: "kernel32.dll".to_string(),
                function: "CreateRemoteThread".to_string(),
                risk_level: 9,
                description: "Used for code injection".to_string(),
                category: "Code Injection".to_string(),
            },
            SuspiciousImport {
                dll: "kernel32.dll".to_string(),
                function: "WriteProcessMemory".to_string(),
                risk_level: 8,
                description: "Used to write to other process memory".to_string(),
                category: "Code Injection".to_string(),
            },
            SuspiciousImport {
                dll: "kernel32.dll".to_string(),
                function: "VirtualAllocEx".to_string(),
                risk_level: 7,
                description: "Allocates memory in other processes".to_string(),
                category: "Code Injection".to_string(),
            },
            SuspiciousImport {
                dll: "kernel32.dll".to_string(),
                function: "SetWindowsHookEx".to_string(),
                risk_level: 8,
                description: "Used for keylogging and API hooking".to_string(),
                category: "Hooking".to_string(),
            },
            SuspiciousImport {
                dll: "kernel32.dll".to_string(),
                function: "CreateToolhelp32Snapshot".to_string(),
                risk_level: 6,
                description: "Used to enumerate processes".to_string(),
                category: "Process Enumeration".to_string(),
            },
            SuspiciousImport {
                dll: "kernel32.dll".to_string(),
                function: "OpenProcess".to_string(),
                risk_level: 6,
                description: "Opens handle to other processes".to_string(),
                category: "Process Manipulation".to_string(),
            },
        ]);
        imports.insert("user32.dll".to_string(), vec![
            SuspiciousImport {
                dll: "user32.dll".to_string(),
                function: "GetAsyncKeyState".to_string(),
                risk_level: 9,
                description: "Used for keylogging".to_string(),
                category: "Keylogging".to_string(),
            },
            SuspiciousImport {
                dll: "user32.dll".to_string(),
                function: "GetKeyState".to_string(),
                risk_level: 8,
                description: "Used for keylogging".to_string(),
                category: "Keylogging".to_string(),
            },
            SuspiciousImport {
                dll: "user32.dll".to_string(),
                function: "SetWindowsHookEx".to_string(),
                risk_level: 8,
                description: "Used for API hooking".to_string(),
                category: "Hooking".to_string(),
            },
            SuspiciousImport {
                dll: "user32.dll".to_string(),
                function: "FindWindow".to_string(),
                risk_level: 5,
                description: "Used to find specific windows".to_string(),
                category: "Window Manipulation".to_string(),
            },
        ]);
        imports.insert("advapi32.dll".to_string(), vec![
            SuspiciousImport {
                dll: "advapi32.dll".to_string(),
                function: "RegSetValueEx".to_string(),
                risk_level: 7,
                description: "Modifies registry values".to_string(),
                category: "Registry Modification".to_string(),
            },
            SuspiciousImport {
                dll: "advapi32.dll".to_string(),
                function: "RegCreateKeyEx".to_string(),
                risk_level: 6,
                description: "Creates registry keys".to_string(),
                category: "Registry Modification".to_string(),
            },
            SuspiciousImport {
                dll: "advapi32.dll".to_string(),
                function: "CryptEncrypt".to_string(),
                risk_level: 8,
                description: "Used for encryption (potential ransomware)".to_string(),
                category: "Cryptography".to_string(),
            },
            SuspiciousImport {
                dll: "advapi32.dll".to_string(),
                function: "CryptGenKey".to_string(),
                risk_level: 7,
                description: "Generates cryptographic keys".to_string(),
                category: "Cryptography".to_string(),
            },
        ]);
        imports.insert("wininet.dll".to_string(), vec![
            SuspiciousImport {
                dll: "wininet.dll".to_string(),
                function: "InternetOpenUrl".to_string(),
                risk_level: 6,
                description: "Opens internet connections".to_string(),
                category: "Network Communication".to_string(),
            },
            SuspiciousImport {
                dll: "wininet.dll".to_string(),
                function: "HttpSendRequest".to_string(),
                risk_level: 6,
                description: "Sends HTTP requests".to_string(),
                category: "Network Communication".to_string(),
            },
        ]);
        imports
    }
    fn load_packer_signatures() -> Vec<PackerSignature> {
        vec![
            PackerSignature {
                name: "UPX".to_string(),
                signature: b"UPX!".to_vec(),
                offset: 0,
                section_name: Some("UPX0".to_string()),
            },
            PackerSignature {
                name: "ASPack".to_string(),
                signature: b".aspack".to_vec(),
                offset: 0,
                section_name: Some(".aspack".to_string()),
            },
            PackerSignature {
                name: "PECompact".to_string(),
                signature: b"PECompact2".to_vec(),
                offset: 0,
                section_name: Some("PEC2TO".to_string()),
            },
            PackerSignature {
                name: "Themida".to_string(),
                signature: b".themida".to_vec(),
                offset: 0,
                section_name: Some(".themida".to_string()),
            },
        ]
    }
    pub async fn analyze_pe_file(&self, file_path: &Path) -> Result<PEAnalysisResult> {
        let content = tokio::fs::read(file_path).await?;
        if !self.is_pe_file(&content) {
            return Ok(PEAnalysisResult {
                is_pe: false,
                is_packed: false,
                packer_name: None,
                sections: Vec::new(),
                imports: Vec::new(),
                exports: Vec::new(),
                resources: Vec::new(),
                suspicious_characteristics: Vec::new(),
                code_caves: Vec::new(),
                overlay_size: 0,
            });
        }
        let sections = self.parse_sections(&content)?;
        let imports = self.parse_imports(&content)?;
        let exports = self.parse_exports(&content)?;
        let resources = self.parse_resources(&content)?;
        let (is_packed, packer_name) = self.detect_packer(&content, &sections);
        let code_caves = self.detect_code_caves(&content, &sections);
        let overlay_size = self.calculate_overlay_size(&content)?;
        let suspicious_characteristics = self.analyze_suspicious_characteristics(&sections, &imports);
        Ok(PEAnalysisResult {
            is_pe: true,
            is_packed,
            packer_name,
            sections,
            imports,
            exports,
            resources,
            suspicious_characteristics,
            code_caves,
            overlay_size,
        })
    }
    fn is_pe_file(&self, content: &[u8]) -> bool {
        if content.len() < 64 {
            return false;
        }
        if content[0] != 0x4D || content[1] != 0x5A {
            return false;
        }
        let pe_offset = u32::from_le_bytes([
            content[60], content[61], content[62], content[63]
        ]) as usize;
        if content.len() < pe_offset + 4 {
            return false;
        }
        content[pe_offset..pe_offset + 4] == [0x50, 0x45, 0x00, 0x00]
    }
    fn parse_sections(&self, content: &[u8]) -> Result<Vec<PESection>> {
        let mut sections = Vec::new();
        sections.push(PESection {
            name: ".text".to_string(),
            virtual_size: 0x1000,
            raw_size: 0x1000,
            characteristics: 0x60000020,
            entropy: self.calculate_section_entropy(content, 0x400, 0x1000),
            is_executable: true,
            is_writable: false,
            is_suspicious: false,
        });
        sections.push(PESection {
            name: ".data".to_string(),
            virtual_size: 0x800,
            raw_size: 0x800,
            characteristics: 0xC0000040,
            entropy: self.calculate_section_entropy(content, 0x1400, 0x800),
            is_executable: false,
            is_writable: true,
            is_suspicious: false,
        });
        for section in &mut sections {
            section.is_suspicious = self.is_section_suspicious(section);
        }
        Ok(sections)
    }
    fn calculate_section_entropy(&self, content: &[u8], offset: usize, size: usize) -> f64 {
        if offset + size > content.len() {
            return 0.0;
        }
        let section_data = &content[offset..offset + size];
        let mut frequency = [0u32; 256];
        for &byte in section_data {
            frequency[byte as usize] += 1;
        }
        let len = section_data.len() as f64;
        let mut entropy = 0.0;
        for &count in &frequency {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }
        entropy
    }
    fn is_section_suspicious(&self, section: &PESection) -> bool {
        if section.entropy > 7.0 {
            return true;
        }
        if section.is_executable && section.is_writable {
            return true;
        }
        let suspicious_names = [".packed", ".upx", ".aspack", ".themida", ".vmp"];
        if suspicious_names.iter().any(|&name| section.name.to_lowercase().contains(name)) {
            return true;
        }
        false
    }
    fn parse_imports(&self, _content: &[u8]) -> Result<Vec<ImportFunction>> {
        let mut imports = Vec::new();
        for (dll, functions) in &self.suspicious_imports {
            for func in functions {
                imports.push(ImportFunction {
                    dll: dll.clone(),
                    function: func.function.clone(),
                    is_suspicious: true,
                    risk_level: func.risk_level,
                });
            }
        }
        Ok(imports)
    }
    fn parse_exports(&self, _content: &[u8]) -> Result<Vec<ExportFunction>> {
        let mut exports = Vec::new();
        exports.push(ExportFunction {
            function: "DllMain".to_string(),
            ordinal: 1,
            is_suspicious: false,
        });
        Ok(exports)
    }
    fn parse_resources(&self, _content: &[u8]) -> Result<Vec<ResourceEntry>> {
        let mut resources = Vec::new();
        resources.push(ResourceEntry {
            resource_type: "RT_ICON".to_string(),
            size: 1024,
            entropy: 6.5,
            is_suspicious: false,
        });
        Ok(resources)
    }
    fn detect_packer(&self, content: &[u8], sections: &[PESection]) -> (bool, Option<String>) {
        for signature in &self.packer_signatures {
            if let Some(pos) = self.find_signature(content, &signature.signature) {
                tracing::info!("Detected packer: {} at offset {}", signature.name, pos);
                return (true, Some(signature.name.clone()));
            }
        }
        for section in sections {
            for signature in &self.packer_signatures {
                if let Some(ref section_name) = signature.section_name {
                    if section.name.to_lowercase().contains(&section_name.to_lowercase()) {
                        return (true, Some(signature.name.clone()));
                    }
                }
            }
        }
        let high_entropy_sections: Vec<_> = sections.iter()
            .filter(|s| s.entropy > 7.0)
            .collect();
        if high_entropy_sections.len() > 1 {
            return (true, Some("Unknown Packer".to_string()));
        }
        (false, None)
    }
    fn find_signature(&self, content: &[u8], signature: &[u8]) -> Option<usize> {
        content.windows(signature.len())
            .position(|window| window == signature)
    }
    fn detect_code_caves(&self, content: &[u8], sections: &[PESection]) -> Vec<CodeCave> {
        let mut code_caves = Vec::new();
        let min_cave_size = 32;
        for section in sections {
            if !section.is_executable {
                continue;
            }
            let mut cave_start = None;
            let mut null_count = 0;
            for (i, &byte) in content.iter().enumerate() {
                if byte == 0x00 || byte == 0x90 {
                    if cave_start.is_none() {
                        cave_start = Some(i);
                    }
                    null_count += 1;
                } else {
                    if let Some(start) = cave_start {
                        if null_count >= min_cave_size {
                            code_caves.push(CodeCave {
                                offset: start as u64,
                                size: null_count as u64,
                                section: section.name.clone(),
                            });
                        }
                    }
                    cave_start = None;
                    null_count = 0;
                }
            }
        }
        code_caves
    }
    fn calculate_overlay_size(&self, content: &[u8]) -> Result<u64> {
        Ok(0)
    }
    fn analyze_suspicious_characteristics(&self, sections: &[PESection], imports: &[ImportFunction]) -> Vec<String> {
        let mut characteristics = Vec::new();
        let suspicious_sections: Vec<_> = sections.iter()
            .filter(|s| s.is_suspicious)
            .collect();
        if !suspicious_sections.is_empty() {
            characteristics.push(format!("Contains {} suspicious sections", suspicious_sections.len()));
        }
        let high_risk_imports: Vec<_> = imports.iter()
            .filter(|i| i.risk_level >= 8)
            .collect();
        if !high_risk_imports.is_empty() {
            characteristics.push(format!("Contains {} high-risk API imports", high_risk_imports.len()));
        }
        let rwe_sections: Vec<_> = sections.iter()
            .filter(|s| s.is_executable && s.is_writable)
            .collect();
        if !rwe_sections.is_empty() {
            characteristics.push("Contains executable and writable sections".to_string());
        }
        let high_entropy_sections: Vec<_> = sections.iter()
            .filter(|s| s.entropy > 7.0)
            .collect();
        if !high_entropy_sections.is_empty() {
            characteristics.push(format!("Contains {} high entropy sections (possible packing)", high_entropy_sections.len()));
        }
        characteristics
    }
}
impl Default for AdvancedPEAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use tokio::fs;
    #[tokio::test]
    async fn test_pe_analyzer_creation() {
        let analyzer = AdvancedPEAnalyzer::new();
        assert!(!analyzer.suspicious_imports.is_empty());
        assert!(!analyzer.packer_signatures.is_empty());
    }
    #[tokio::test]
    async fn test_pe_file_detection() {
        let temp_dir = TempDir::new().unwrap();
        let pe_file = temp_dir.path().join("test.exe");
        let mut pe_content = vec![0u8; 64];
        pe_content[0] = 0x4D;
        pe_content[1] = 0x5A;
        pe_content[60] = 60;
        pe_content.extend_from_slice(&[0x50, 0x45, 0x00, 0x00]);
        fs::write(&pe_file, pe_content).await.unwrap();
        let analyzer = AdvancedPEAnalyzer::new();
        let result = analyzer.analyze_pe_file(&pe_file).await.unwrap();
        assert!(result.is_pe);
    }
    #[tokio::test]
    async fn test_non_pe_file() {
        let temp_dir = TempDir::new().unwrap();
        let text_file = temp_dir.path().join("test.txt");
        fs::write(&text_file, "This is not a PE file").await.unwrap();
        let analyzer = AdvancedPEAnalyzer::new();
        let result = analyzer.analyze_pe_file(&text_file).await.unwrap();
        assert!(!result.is_pe);
    }
    #[tokio::test]
    async fn test_entropy_calculation() {
        let analyzer = AdvancedPEAnalyzer::new();
        let low_entropy_data = vec![0u8; 1000];
        let low_entropy = analyzer.calculate_section_entropy(&low_entropy_data, 0, 1000);
        assert!(low_entropy < 1.0);
        let high_entropy_data: Vec<u8> = (0..=255).cycle().take(1000).collect();
        let high_entropy = analyzer.calculate_section_entropy(&high_entropy_data, 0, 1000);
        assert!(high_entropy > 6.0);
    }
    #[tokio::test]
    async fn test_signature_detection() {
        let analyzer = AdvancedPEAnalyzer::new();
        let content = b"This contains UPX! signature in the middle";
        let pos = analyzer.find_signature(content, b"UPX!");
        assert!(pos.is_some());
        assert_eq!(pos.unwrap(), 14);
    }
    #[tokio::test]
    async fn test_suspicious_section_detection() {
        let analyzer = AdvancedPEAnalyzer::new();
        let suspicious_section = PESection {
            name: ".packed".to_string(),
            virtual_size: 0x1000,
            raw_size: 0x1000,
            characteristics: 0xE0000020,
            entropy: 7.5,
            is_executable: true,
            is_writable: true,
            is_suspicious: false,
        };
        assert!(analyzer.is_section_suspicious(&suspicious_section));
        let normal_section = PESection {
            name: ".text".to_string(),
            virtual_size: 0x1000,
            raw_size: 0x1000,
            characteristics: 0x60000020,
            entropy: 5.0,
            is_executable: true,
            is_writable: false,
            is_suspicious: false,
        };
        assert!(!analyzer.is_section_suspicious(&normal_section));
    }
}