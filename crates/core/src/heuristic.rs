use crate::{Result, ThreatInfo, ThreatType, ThreatSeverity, DetectionMethod, FileInfo};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

/// Heuristic analyzer for detecting suspicious behavior patterns
pub struct HeuristicAnalyzer {
    rules: Vec<HeuristicRule>,
    pe_analyzer: PEAnalyzer,
    behavior_analyzer: BehaviorAnalyzer,
    entropy_analyzer: EntropyAnalyzer,
    string_analyzer: StringAnalyzer,
}

/// Heuristic rule for pattern matching
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeuristicRule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub severity: ThreatSeverity,
    pub threat_type: ThreatType,
    pub conditions: Vec<HeuristicCondition>,
    pub weight: f32,
    pub enabled: bool,
}

/// Condition for heuristic rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HeuristicCondition {
    /// File size condition
    FileSize { min: Option<u64>, max: Option<u64> },
    /// File extension condition
    FileExtension { extensions: Vec<String> },
    /// Entropy condition
    Entropy { min: f64, max: f64 },
    /// String pattern condition
    StringPattern { pattern: String, count: usize },
    /// PE section condition
    PESection { name: String, characteristics: u32 },
    /// Import function condition
    ImportFunction { dll: String, function: String },
    /// Export function condition
    ExportFunction { function: String },
    /// Resource condition
    Resource { resource_type: String, size: Option<u64> },
    /// Packer detection
    PackerDetection { packer_name: String },
    /// Code cave detection
    CodeCave { min_size: u64 },
    /// Suspicious strings
    SuspiciousStrings { patterns: Vec<String>, threshold: usize },
}

/// Heuristic analysis result
#[derive(Debug, Clone)]
pub struct HeuristicResult {
    pub rule_matches: Vec<RuleMatch>,
    pub pe_analysis: Option<PEAnalysisResult>,
    pub behavior_analysis: BehaviorAnalysisResult,
    pub entropy_analysis: EntropyAnalysisResult,
    pub string_analysis: StringAnalysisResult,
    pub overall_score: f32,
    pub threat_level: ThreatSeverity,
}

/// Rule match result
#[derive(Debug, Clone)]
pub struct RuleMatch {
    pub rule: HeuristicRule,
    pub confidence: f32,
    pub matched_conditions: Vec<String>,
    pub evidence: HashMap<String, String>,
}

/// PE file analysis result
#[derive(Debug, Clone)]
pub struct PEAnalysisResult {
    pub is_pe: bool,
    pub is_packed: bool,
    pub packer_name: Option<String>,
    pub sections: Vec<PESection>,
    pub imports: Vec<ImportFunction>,
    pub exports: Vec<ExportFunction>,
    pub resources: Vec<ResourceEntry>,
    pub suspicious_characteristics: Vec<String>,
    pub code_caves: Vec<CodeCave>,
    pub overlay_size: u64,
}

/// PE section information
#[derive(Debug, Clone)]
pub struct PESection {
    pub name: String,
    pub virtual_size: u32,
    pub raw_size: u32,
    pub characteristics: u32,
    pub entropy: f64,
    pub is_executable: bool,
    pub is_writable: bool,
    pub is_suspicious: bool,
}

/// Import function information
#[derive(Debug, Clone)]
pub struct ImportFunction {
    pub dll: String,
    pub function: String,
    pub is_suspicious: bool,
    pub risk_level: u8,
}

/// Export function information
#[derive(Debug, Clone)]
pub struct ExportFunction {
    pub function: String,
    pub ordinal: u16,
    pub is_suspicious: bool,
}

/// Resource entry information
#[derive(Debug, Clone)]
pub struct ResourceEntry {
    pub resource_type: String,
    pub size: u64,
    pub entropy: f64,
    pub is_suspicious: bool,
}

/// Code cave information
#[derive(Debug, Clone)]
pub struct CodeCave {
    pub offset: u64,
    pub size: u64,
    pub section: String,
}

/// Behavior analysis result
#[derive(Debug, Clone)]
pub struct BehaviorAnalysisResult {
    pub suspicious_behaviors: Vec<SuspiciousBehavior>,
    pub api_calls: Vec<APICall>,
    pub network_indicators: Vec<NetworkIndicator>,
    pub file_operations: Vec<FileOperation>,
    pub registry_operations: Vec<RegistryOperation>,
    pub behavior_score: f32,
}

/// Suspicious behavior pattern
#[derive(Debug, Clone)]
pub struct SuspiciousBehavior {
    pub behavior_type: String,
    pub description: String,
    pub severity: ThreatSeverity,
    pub evidence: Vec<String>,
    pub confidence: f32,
}

/// API call information
#[derive(Debug, Clone)]
pub struct APICall {
    pub dll: String,
    pub function: String,
    pub is_suspicious: bool,
    pub risk_level: u8,
    pub description: String,
}

/// Network indicator
#[derive(Debug, Clone)]
pub struct NetworkIndicator {
    pub indicator_type: String,
    pub value: String,
    pub is_suspicious: bool,
    pub description: String,
}

/// File operation indicator
#[derive(Debug, Clone)]
pub struct FileOperation {
    pub operation: String,
    pub target: String,
    pub is_suspicious: bool,
    pub description: String,
}

/// Registry operation indicator
#[derive(Debug, Clone)]
pub struct RegistryOperation {
    pub operation: String,
    pub key: String,
    pub value: Option<String>,
    pub is_suspicious: bool,
    pub description: String,
}

/// Entropy analysis result
#[derive(Debug, Clone)]
pub struct EntropyAnalysisResult {
    pub overall_entropy: f64,
    pub section_entropies: HashMap<String, f64>,
    pub high_entropy_sections: Vec<String>,
    pub is_packed: bool,
    pub entropy_score: f32,
}

/// String analysis result
#[derive(Debug, Clone)]
pub struct StringAnalysisResult {
    pub suspicious_strings: Vec<SuspiciousString>,
    pub crypto_strings: Vec<String>,
    pub network_strings: Vec<String>,
    pub file_strings: Vec<String>,
    pub registry_strings: Vec<String>,
    pub string_score: f32,
}

/// Suspicious string information
#[derive(Debug, Clone)]
pub struct SuspiciousString {
    pub string: String,
    pub category: String,
    pub risk_level: u8,
    pub description: String,
}

impl HeuristicAnalyzer {
    /// Create a new heuristic analyzer
    pub fn new() -> Self {
        Self {
            rules: Self::load_default_rules(),
            pe_analyzer: PEAnalyzer::new(),
            behavior_analyzer: BehaviorAnalyzer::new(),
            entropy_analyzer: EntropyAnalyzer::new(),
            string_analyzer: StringAnalyzer::new(),
        }
    }

    /// Load default heuristic rules
    fn load_default_rules() -> Vec<HeuristicRule> {
        vec![
            // High entropy packed executable
            HeuristicRule {
                id: "HEUR_001".to_string(),
                name: "High Entropy Packed Executable".to_string(),
                description: "Executable with high entropy indicating packing or encryption".to_string(),
                severity: ThreatSeverity::Medium,
                threat_type: ThreatType::Suspicious,
                conditions: vec![
                    HeuristicCondition::FileExtension { 
                        extensions: vec!["exe".to_string(), "dll".to_string()] 
                    },
                    HeuristicCondition::Entropy { min: 7.0, max: 8.0 },
                ],
                weight: 0.7,
                enabled: true,
            },
            
            // Suspicious API imports
            HeuristicRule {
                id: "HEUR_002".to_string(),
                name: "Suspicious API Imports".to_string(),
                description: "Executable imports suspicious Windows APIs".to_string(),
                severity: ThreatSeverity::High,
                threat_type: ThreatType::Trojan,
                conditions: vec![
                    HeuristicCondition::ImportFunction { 
                        dll: "kernel32.dll".to_string(), 
                        function: "CreateRemoteThread".to_string() 
                    },
                    HeuristicCondition::ImportFunction { 
                        dll: "kernel32.dll".to_string(), 
                        function: "WriteProcessMemory".to_string() 
                    },
                ],
                weight: 0.9,
                enabled: true,
            },
            
            // Code injection patterns
            HeuristicRule {
                id: "HEUR_003".to_string(),
                name: "Code Injection Patterns".to_string(),
                description: "Patterns indicating code injection techniques".to_string(),
                severity: ThreatSeverity::High,
                threat_type: ThreatType::Trojan,
                conditions: vec![
                    HeuristicCondition::SuspiciousStrings { 
                        patterns: vec![
                            "VirtualAllocEx".to_string(),
                            "WriteProcessMemory".to_string(),
                            "CreateRemoteThread".to_string(),
                        ], 
                        threshold: 2 
                    },
                ],
                weight: 0.8,
                enabled: true,
            },
            
            // Ransomware indicators
            HeuristicRule {
                id: "HEUR_004".to_string(),
                name: "Ransomware Indicators".to_string(),
                description: "Behavioral patterns indicating ransomware".to_string(),
                severity: ThreatSeverity::Critical,
                threat_type: ThreatType::Ransomware,
                conditions: vec![
                    HeuristicCondition::SuspiciousStrings { 
                        patterns: vec![
                            "CryptEncrypt".to_string(),
                            "CryptGenKey".to_string(),
                            "bitcoin".to_string(),
                            "ransom".to_string(),
                            "decrypt".to_string(),
                        ], 
                        threshold: 3 
                    },
                ],
                weight: 0.95,
                enabled: true,
            },
            
            // Keylogger patterns
            HeuristicRule {
                id: "HEUR_005".to_string(),
                name: "Keylogger Patterns".to_string(),
                description: "Patterns indicating keylogging functionality".to_string(),
                severity: ThreatSeverity::High,
                threat_type: ThreatType::Spyware,
                conditions: vec![
                    HeuristicCondition::SuspiciousStrings { 
                        patterns: vec![
                            "GetAsyncKeyState".to_string(),
                            "SetWindowsHookEx".to_string(),
                            "keylog".to_string(),
                        ], 
                        threshold: 2 
                    },
                ],
                weight: 0.85,
                enabled: true,
            },
        ]
    }

    /// Analyze file using heuristic methods
    pub async fn analyze_file(&self, file_path: &Path, file_info: &FileInfo) -> Result<HeuristicResult> {
        let mut rule_matches = Vec::new();
        let mut overall_score = 0.0f32;

        // Perform PE analysis if it's an executable
        let pe_analysis = if file_info.is_executable {
            Some(self.pe_analyzer.analyze_pe_file(file_path).await?)
        } else {
            None
        };

        // Perform behavior analysis
        let behavior_analysis = self.behavior_analyzer.analyze_behavior(file_path, file_info).await?;

        // Perform entropy analysis
        let entropy_analysis = self.entropy_analyzer.analyze_entropy(file_path).await?;

        // Perform string analysis
        let string_analysis = self.string_analyzer.analyze_strings(file_path).await?;

        // Apply heuristic rules
        for rule in &self.rules {
            if !rule.enabled {
                continue;
            }

            let rule_match = self.evaluate_rule(rule, file_info, &pe_analysis, &behavior_analysis, &entropy_analysis, &string_analysis).await?;
            
            if let Some(matched_rule) = rule_match {
                overall_score += matched_rule.confidence * rule.weight;
                rule_matches.push(matched_rule);
            }
        }

        // Calculate threat level based on overall score
        let threat_level = match overall_score {
            score if score >= 0.8 => ThreatSeverity::Critical,
            score if score >= 0.6 => ThreatSeverity::High,
            score if score >= 0.4 => ThreatSeverity::Medium,
            score if score >= 0.2 => ThreatSeverity::Low,
            _ => ThreatSeverity::Low,
        };

        Ok(HeuristicResult {
            rule_matches,
            pe_analysis,
            behavior_analysis,
            entropy_analysis,
            string_analysis,
            overall_score,
            threat_level,
        })
    }

    /// Evaluate a single heuristic rule
    async fn evaluate_rule(
        &self,
        rule: &HeuristicRule,
        file_info: &FileInfo,
        pe_analysis: &Option<PEAnalysisResult>,
        behavior_analysis: &BehaviorAnalysisResult,
        entropy_analysis: &EntropyAnalysisResult,
        string_analysis: &StringAnalysisResult,
    ) -> Result<Option<RuleMatch>> {
        let mut matched_conditions = Vec::new();
        let mut evidence = HashMap::new();
        let mut condition_matches = 0;

        for condition in &rule.conditions {
            let (is_match, condition_evidence) = self.evaluate_condition(
                condition, 
                file_info, 
                pe_analysis, 
                behavior_analysis, 
                entropy_analysis, 
                string_analysis
            ).await?;

            if is_match {
                condition_matches += 1;
                matched_conditions.push(format!("{:?}", condition));
                evidence.extend(condition_evidence);
            }
        }

        // Rule matches if all conditions are met
        if condition_matches == rule.conditions.len() && condition_matches > 0 {
            let confidence = (condition_matches as f32) / (rule.conditions.len() as f32);
            
            Ok(Some(RuleMatch {
                rule: rule.clone(),
                confidence,
                matched_conditions,
                evidence,
            }))
        } else {
            Ok(None)
        }
    }

    /// Evaluate a single condition
    async fn evaluate_condition(
        &self,
        condition: &HeuristicCondition,
        file_info: &FileInfo,
        pe_analysis: &Option<PEAnalysisResult>,
        _behavior_analysis: &BehaviorAnalysisResult,
        entropy_analysis: &EntropyAnalysisResult,
        string_analysis: &StringAnalysisResult,
    ) -> Result<(bool, HashMap<String, String>)> {
        let mut evidence = HashMap::new();

        let is_match = match condition {
            HeuristicCondition::FileSize { min, max } => {
                let size = file_info.size;
                let min_ok = min.map_or(true, |m| size >= m);
                let max_ok = max.map_or(true, |m| size <= m);
                evidence.insert("file_size".to_string(), size.to_string());
                min_ok && max_ok
            }

            HeuristicCondition::FileExtension { extensions } => {
                if let Some(ref ext) = file_info.extension {
                    let matches = extensions.contains(ext);
                    evidence.insert("file_extension".to_string(), ext.clone());
                    matches
                } else {
                    false
                }
            }

            HeuristicCondition::Entropy { min, max } => {
                let entropy = entropy_analysis.overall_entropy;
                evidence.insert("entropy".to_string(), entropy.to_string());
                entropy >= *min && entropy <= *max
            }

            HeuristicCondition::StringPattern { pattern, count } => {
                let matches = string_analysis.suspicious_strings.iter()
                    .filter(|s| s.string.contains(pattern))
                    .count();
                evidence.insert("string_matches".to_string(), matches.to_string());
                matches >= *count
            }

            HeuristicCondition::PESection { name, characteristics } => {
                if let Some(ref pe) = pe_analysis {
                    let section_match = pe.sections.iter()
                        .any(|s| s.name == *name && (s.characteristics & characteristics) != 0);
                    evidence.insert("pe_section".to_string(), name.clone());
                    section_match
                } else {
                    false
                }
            }

            HeuristicCondition::ImportFunction { dll, function } => {
                if let Some(ref pe) = pe_analysis {
                    let import_match = pe.imports.iter()
                        .any(|i| i.dll.to_lowercase() == dll.to_lowercase() && 
                                 i.function.to_lowercase() == function.to_lowercase());
                    evidence.insert("import_function".to_string(), format!("{}:{}", dll, function));
                    import_match
                } else {
                    false
                }
            }

            HeuristicCondition::ExportFunction { function } => {
                if let Some(ref pe) = pe_analysis {
                    let export_match = pe.exports.iter()
                        .any(|e| e.function.to_lowercase() == function.to_lowercase());
                    evidence.insert("export_function".to_string(), function.clone());
                    export_match
                } else {
                    false
                }
            }

            HeuristicCondition::Resource { resource_type, size } => {
                if let Some(ref pe) = pe_analysis {
                    let resource_match = pe.resources.iter()
                        .any(|r| r.resource_type == *resource_type && 
                                 size.map_or(true, |s| r.size >= s));
                    evidence.insert("resource_type".to_string(), resource_type.clone());
                    resource_match
                } else {
                    false
                }
            }

            HeuristicCondition::PackerDetection { packer_name } => {
                if let Some(ref pe) = pe_analysis {
                    let packer_match = pe.is_packed && 
                        pe.packer_name.as_ref().map_or(false, |p| p == packer_name);
                    evidence.insert("packer_detected".to_string(), 
                                   pe.packer_name.clone().unwrap_or_default());
                    packer_match
                } else {
                    false
                }
            }

            HeuristicCondition::CodeCave { min_size } => {
                if let Some(ref pe) = pe_analysis {
                    let cave_match = pe.code_caves.iter()
                        .any(|c| c.size >= *min_size);
                    evidence.insert("code_caves".to_string(), pe.code_caves.len().to_string());
                    cave_match
                } else {
                    false
                }
            }

            HeuristicCondition::SuspiciousStrings { patterns, threshold } => {
                let mut pattern_matches = 0;
                for pattern in patterns {
                    if string_analysis.suspicious_strings.iter()
                        .any(|s| s.string.to_lowercase().contains(&pattern.to_lowercase())) {
                        pattern_matches += 1;
                    }
                }
                evidence.insert("suspicious_string_matches".to_string(), pattern_matches.to_string());
                pattern_matches >= *threshold
            }
        };

        Ok((is_match, evidence))
    }

    /// Convert heuristic results to threat info
    pub fn results_to_threats(&self, results: &HeuristicResult, file_path: &Path, file_hash: &str) -> Result<Vec<ThreatInfo>> {
        let mut threats = Vec::new();

        for rule_match in &results.rule_matches {
            let mut threat = ThreatInfo::new(
                format!("Heuristic.{}", rule_match.rule.name.replace(' ', "")),
                rule_match.rule.threat_type.clone(),
                rule_match.rule.severity.clone(),
                file_path.to_path_buf(),
                file_hash.to_string(),
                DetectionMethod::Heuristic,
            )?;

            // Add evidence as additional info
            for (key, value) in &rule_match.evidence {
                threat.add_info(key.clone(), value.clone());
            }

            threat.add_info("confidence".to_string(), rule_match.confidence.to_string());
            threat.add_info("rule_id".to_string(), rule_match.rule.id.clone());
            threat.add_info("matched_conditions".to_string(), rule_match.matched_conditions.join(", "));

            threats.push(threat);
        }

        Ok(threats)
    }

    /// Add custom heuristic rule
    pub fn add_rule(&mut self, rule: HeuristicRule) {
        self.rules.push(rule);
    }

    /// Remove heuristic rule by ID
    pub fn remove_rule(&mut self, rule_id: &str) {
        self.rules.retain(|r| r.id != rule_id);
    }

    /// Enable/disable rule
    pub fn set_rule_enabled(&mut self, rule_id: &str, enabled: bool) {
        if let Some(rule) = self.rules.iter_mut().find(|r| r.id == rule_id) {
            rule.enabled = enabled;
        }
    }

    /// Get all rules
    pub fn get_rules(&self) -> &[HeuristicRule] {
        &self.rules
    }
}

impl Default for HeuristicAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

/// PE file analyzer
pub struct PEAnalyzer {
    advanced_analyzer: crate::AdvancedPEAnalyzer,
}

impl PEAnalyzer {
    pub fn new() -> Self {
        Self {
            advanced_analyzer: crate::AdvancedPEAnalyzer::new(),
        }
    }

    pub async fn analyze_pe_file(&self, file_path: &Path) -> Result<PEAnalysisResult> {
        self.advanced_analyzer.analyze_pe_file(file_path).await
    }
}

/// Behavior analyzer
pub struct BehaviorAnalyzer;

impl BehaviorAnalyzer {
    pub fn new() -> Self {
        Self
    }

    pub async fn analyze_behavior(&self, _file_path: &Path, _file_info: &FileInfo) -> Result<BehaviorAnalysisResult> {
        // TODO: Implement behavior analysis
        
        Ok(BehaviorAnalysisResult {
            suspicious_behaviors: Vec::new(),
            api_calls: Vec::new(),
            network_indicators: Vec::new(),
            file_operations: Vec::new(),
            registry_operations: Vec::new(),
            behavior_score: 0.0,
        })
    }
}

/// Entropy analyzer
pub struct EntropyAnalyzer;

impl EntropyAnalyzer {
    pub fn new() -> Self {
        Self
    }

    pub async fn analyze_entropy(&self, file_path: &Path) -> Result<EntropyAnalysisResult> {
        let content = tokio::fs::read(file_path).await?;
        let entropy = self.calculate_entropy(&content);
        
        Ok(EntropyAnalysisResult {
            overall_entropy: entropy,
            section_entropies: HashMap::new(),
            high_entropy_sections: Vec::new(),
            is_packed: entropy > 7.0,
            entropy_score: (entropy / 8.0) as f32,
        })
    }

    fn calculate_entropy(&self, data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }

        let mut frequency = [0u32; 256];
        for &byte in data {
            frequency[byte as usize] += 1;
        }

        let len = data.len() as f64;
        let mut entropy = 0.0;

        for &count in &frequency {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }

        entropy
    }
}

/// String analyzer
pub struct StringAnalyzer;

impl StringAnalyzer {
    pub fn new() -> Self {
        Self
    }

    pub async fn analyze_strings(&self, file_path: &Path) -> Result<StringAnalysisResult> {
        let content = tokio::fs::read(file_path).await?;
        let strings = self.extract_strings(&content, 4);
        
        let suspicious_strings = self.identify_suspicious_strings(&strings);
        let crypto_strings = self.identify_crypto_strings(&strings);
        let network_strings = self.identify_network_strings(&strings);
        let file_strings = self.identify_file_strings(&strings);
        let registry_strings = self.identify_registry_strings(&strings);

        let string_score = self.calculate_string_score(&suspicious_strings);

        Ok(StringAnalysisResult {
            suspicious_strings,
            crypto_strings,
            network_strings,
            file_strings,
            registry_strings,
            string_score,
        })
    }

    fn extract_strings(&self, data: &[u8], min_length: usize) -> Vec<String> {
        let mut strings = Vec::new();
        let mut current_string = String::new();

        for &byte in data {
            if byte.is_ascii_graphic() || byte == b' ' {
                current_string.push(byte as char);
            } else {
                if current_string.len() >= min_length {
                    strings.push(current_string.clone());
                }
                current_string.clear();
            }
        }

        if current_string.len() >= min_length {
            strings.push(current_string);
        }

        strings
    }

    fn identify_suspicious_strings(&self, strings: &[String]) -> Vec<SuspiciousString> {
        let suspicious_patterns = [
            ("cmd.exe", "Command Execution", 8),
            ("powershell", "PowerShell Execution", 7),
            ("regedit", "Registry Modification", 6),
            ("keylog", "Keylogging", 9),
            ("password", "Password Theft", 7),
            ("backdoor", "Backdoor Functionality", 9),
            ("rootkit", "Rootkit Behavior", 9),
            ("bitcoin", "Cryptocurrency", 8),
            ("ransom", "Ransomware", 10),
            ("encrypt", "Encryption", 6),
            ("decrypt", "Decryption", 6),
            ("virus", "Virus Reference", 8),
            ("malware", "Malware Reference", 8),
            ("trojan", "Trojan Reference", 8),
        ];

        let mut suspicious = Vec::new();

        for string in strings {
            let string_lower = string.to_lowercase();
            for &(pattern, category, risk_level) in &suspicious_patterns {
                if string_lower.contains(pattern) {
                    suspicious.push(SuspiciousString {
                        string: string.clone(),
                        category: category.to_string(),
                        risk_level,
                        description: format!("Contains suspicious pattern: {}", pattern),
                    });
                    break;
                }
            }
        }

        suspicious
    }

    fn identify_crypto_strings(&self, strings: &[String]) -> Vec<String> {
        let crypto_patterns = ["CryptEncrypt", "CryptDecrypt", "CryptGenKey", "AES", "RSA", "MD5", "SHA"];
        
        strings.iter()
            .filter(|s| crypto_patterns.iter().any(|p| s.to_lowercase().contains(&p.to_lowercase())))
            .cloned()
            .collect()
    }

    fn identify_network_strings(&self, strings: &[String]) -> Vec<String> {
        let network_patterns = ["http://", "https://", "ftp://", "socket", "connect", "send", "recv"];
        
        strings.iter()
            .filter(|s| network_patterns.iter().any(|p| s.to_lowercase().contains(&p.to_lowercase())))
            .cloned()
            .collect()
    }

    fn identify_file_strings(&self, strings: &[String]) -> Vec<String> {
        let file_patterns = ["CreateFile", "WriteFile", "ReadFile", "DeleteFile", "MoveFile"];
        
        strings.iter()
            .filter(|s| file_patterns.iter().any(|p| s.to_lowercase().contains(&p.to_lowercase())))
            .cloned()
            .collect()
    }

    fn identify_registry_strings(&self, strings: &[String]) -> Vec<String> {
        let registry_patterns = ["RegOpenKey", "RegSetValue", "RegCreateKey", "HKEY_", "SOFTWARE\\"];
        
        strings.iter()
            .filter(|s| registry_patterns.iter().any(|p| s.to_lowercase().contains(&p.to_lowercase())))
            .cloned()
            .collect()
    }

    fn calculate_string_score(&self, suspicious_strings: &[SuspiciousString]) -> f32 {
        if suspicious_strings.is_empty() {
            return 0.0;
        }

        let total_risk: u32 = suspicious_strings.iter().map(|s| s.risk_level as u32).sum();
        let max_possible_risk = suspicious_strings.len() as u32 * 10;
        
        (total_risk as f32) / (max_possible_risk as f32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use tokio::fs;

    #[tokio::test]
    async fn test_heuristic_analyzer_creation() {
        let analyzer = HeuristicAnalyzer::new();
        assert!(!analyzer.rules.is_empty());
    }

    #[tokio::test]
    async fn test_entropy_calculation() {
        let analyzer = EntropyAnalyzer::new();
        
        // Low entropy data (all zeros)
        let low_entropy_data = vec![0u8; 1000];
        let low_entropy = analyzer.calculate_entropy(&low_entropy_data);
        assert!(low_entropy < 1.0);
        
        // High entropy data (random)
        let high_entropy_data: Vec<u8> = (0..=255).cycle().take(1000).collect();
        let high_entropy = analyzer.calculate_entropy(&high_entropy_data);
        assert!(high_entropy > 6.0);
    }

    #[tokio::test]
    async fn test_string_analysis() {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test.exe");
        
        let content = b"This file contains cmd.exe and powershell.exe and keylog functionality";
        fs::write(&test_file, content).await.unwrap();

        let analyzer = StringAnalyzer::new();
        let result = analyzer.analyze_strings(&test_file).await.unwrap();

        assert!(!result.suspicious_strings.is_empty());
        assert!(result.string_score > 0.0);
    }

    #[tokio::test]
    async fn test_heuristic_rule_evaluation() {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test.exe");
        
        // Create file with suspicious content
        let content = b"This contains cmd.exe powershell.exe keylog password backdoor";
        fs::write(&test_file, content).await.unwrap();

        let file_info = FileInfo {
            path: test_file.clone(),
            size: content.len() as u64,
            modified: std::time::SystemTime::now(),
            created: std::time::SystemTime::now(),
            is_executable: true,
            extension: Some("exe".to_string()),
            mime_type: Some("application/x-msdownload".to_string()),
        };

        let analyzer = HeuristicAnalyzer::new();
        let result = analyzer.analyze_file(&test_file, &file_info).await.unwrap();

        // Should detect some suspicious patterns
        assert!(result.overall_score > 0.0);
        assert!(!result.rule_matches.is_empty());
    }

    #[tokio::test]
    async fn test_threat_conversion() {
        let analyzer = HeuristicAnalyzer::new();
        
        let rule_match = RuleMatch {
            rule: HeuristicRule {
                id: "TEST_001".to_string(),
                name: "Test Rule".to_string(),
                description: "Test description".to_string(),
                severity: ThreatSeverity::High,
                threat_type: ThreatType::Trojan,
                conditions: Vec::new(),
                weight: 0.8,
                enabled: true,
            },
            confidence: 0.9,
            matched_conditions: vec!["condition1".to_string()],
            evidence: {
                let mut map = HashMap::new();
                map.insert("test_key".to_string(), "test_value".to_string());
                map
            },
        };

        let result = HeuristicResult {
            rule_matches: vec![rule_match],
            pe_analysis: None,
            behavior_analysis: BehaviorAnalysisResult {
                suspicious_behaviors: Vec::new(),
                api_calls: Vec::new(),
                network_indicators: Vec::new(),
                file_operations: Vec::new(),
                registry_operations: Vec::new(),
                behavior_score: 0.0,
            },
            entropy_analysis: EntropyAnalysisResult {
                overall_entropy: 5.0,
                section_entropies: HashMap::new(),
                high_entropy_sections: Vec::new(),
                is_packed: false,
                entropy_score: 0.625,
            },
            string_analysis: StringAnalysisResult {
                suspicious_strings: Vec::new(),
                crypto_strings: Vec::new(),
                network_strings: Vec::new(),
                file_strings: Vec::new(),
                registry_strings: Vec::new(),
                string_score: 0.0,
            },
            overall_score: 0.8,
            threat_level: ThreatSeverity::High,
        };

        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test.exe");
        fs::write(&test_file, b"test").await.unwrap();

        let threats = analyzer.results_to_threats(&result, &test_file, "abcd1234").unwrap();
        
        assert_eq!(threats.len(), 1);
        assert_eq!(threats[0].name, "Heuristic.TestRule");
        assert_eq!(threats[0].threat_type, ThreatType::Trojan);
        assert_eq!(threats[0].severity, ThreatSeverity::High);
        assert_eq!(threats[0].detection_method, DetectionMethod::Heuristic);
    }

    #[tokio::test]
    async fn test_rule_management() {
        let mut analyzer = HeuristicAnalyzer::new();
        let initial_count = analyzer.rules.len();

        // Add a custom rule
        let custom_rule = HeuristicRule {
            id: "CUSTOM_001".to_string(),
            name: "Custom Test Rule".to_string(),
            description: "Custom test description".to_string(),
            severity: ThreatSeverity::Medium,
            threat_type: ThreatType::Suspicious,
            conditions: vec![
                HeuristicCondition::FileExtension { 
                    extensions: vec!["test".to_string()] 
                }
            ],
            weight: 0.5,
            enabled: true,
        };

        analyzer.add_rule(custom_rule);
        assert_eq!(analyzer.rules.len(), initial_count + 1);

        // Disable the rule
        analyzer.set_rule_enabled("CUSTOM_001", false);
        let rule = analyzer.rules.iter().find(|r| r.id == "CUSTOM_001").unwrap();
        assert!(!rule.enabled);

        // Remove the rule
        analyzer.remove_rule("CUSTOM_001");
        assert_eq!(analyzer.rules.len(), initial_count);
    }
}