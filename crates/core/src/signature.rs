/// Signature database and YARA engine integration

use crate::{Result, ThreatInfo, ThreatType, ThreatSeverity, DetectionMethod};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use chrono::{DateTime, Utc};
use yara::{Compiler, Rules, YaraError};

/// Signature database manager
pub struct SignatureDatabase {
    /// Compiled YARA rules
    rules: Arc<RwLock<Option<Rules>>>,
    /// Signature metadata
    signatures: Arc<RwLock<HashMap<String, SignatureMetadata>>>,
    /// Database version
    version: Arc<RwLock<String>>,
    /// Last update time
    last_update: Arc<RwLock<Option<DateTime<Utc>>>>,
    /// Database file path
    database_path: PathBuf,
}

/// Metadata for a signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureMetadata {
    pub name: String,
    pub threat_type: ThreatType,
    pub severity: ThreatSeverity,
    pub description: String,
    pub author: String,
    pub date: DateTime<Utc>,
    pub version: String,
    pub tags: Vec<String>,
    pub references: Vec<String>,
}

/// Signature match result
#[derive(Debug, Clone)]
pub struct SignatureMatch {
    pub rule_name: String,
    pub metadata: SignatureMetadata,
    pub matches: Vec<MatchInstance>,
}

/// Individual match instance
#[derive(Debug, Clone)]
pub struct MatchInstance {
    pub offset: u64,
    pub length: u64,
    pub matched_data: Vec<u8>,
    pub string_identifier: Option<String>,
}

/// Signature compilation statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompilationStats {
    pub total_rules: u32,
    pub compiled_rules: u32,
    pub failed_rules: u32,
    pub compilation_time_ms: u64,
    pub memory_usage_bytes: u64,
}

impl SignatureDatabase {
    /// Create a new signature database
    pub fn new(database_path: PathBuf) -> Self {
        Self {
            rules: Arc::new(RwLock::new(None)),
            signatures: Arc::new(RwLock::new(HashMap::new())),
            version: Arc::new(RwLock::new("0.0.0".to_string())),
            last_update: Arc::new(RwLock::new(None)),
            database_path,
        }
    }

    /// Load signatures from YARA rules files
    pub fn load_signatures(&self, rules_paths: &[PathBuf]) -> Result<CompilationStats> {
        let start_time = std::time::Instant::now();
        let mut compiler = Compiler::new()?;
        let mut total_rules = 0u32;
        let mut failed_rules = 0u32;
        let mut signatures = HashMap::new();

        // Add each rules file to the compiler
        for rules_path in rules_paths {
            match self.load_rules_file(&mut compiler, rules_path, &mut signatures) {
                Ok(count) => {
                    total_rules += count;
                    tracing::info!("Loaded {} rules from {}", count, rules_path.display());
                }
                Err(e) => {
                    failed_rules += 1;
                    tracing::error!("Failed to load rules from {}: {}", rules_path.display(), e);
                }
            }
        }

        // Compile all rules
        let rules = compiler.compile_rules()?;
        let compiled_rules = total_rules - failed_rules;

        // Update internal state
        {
            let mut rules_lock = self.rules.write().unwrap();
            *rules_lock = Some(rules);
        }

        {
            let mut signatures_lock = self.signatures.write().unwrap();
            *signatures_lock = signatures;
        }

        {
            let mut last_update_lock = self.last_update.write().unwrap();
            *last_update_lock = Some(Utc::now());
        }

        let compilation_time_ms = start_time.elapsed().as_millis() as u64;
        let memory_usage_bytes = self.estimate_memory_usage();

        let stats = CompilationStats {
            total_rules,
            compiled_rules,
            failed_rules,
            compilation_time_ms,
            memory_usage_bytes,
        };

        tracing::info!(
            "Signature database loaded: {} rules compiled, {} failed, {}ms",
            compiled_rules, failed_rules, compilation_time_ms
        );

        Ok(stats)
    }

    /// Load a single YARA rules file
    fn load_rules_file(
        &self,
        compiler: &mut Compiler,
        rules_path: &Path,
        signatures: &mut HashMap<String, SignatureMetadata>,
    ) -> Result<u32> {
        let rules_content = std::fs::read_to_string(rules_path)?;
        let mut rule_count = 0u32;

        // Parse metadata from YARA rules
        for line in rules_content.lines() {
            if line.trim().starts_with("rule ") {
                if let Some(metadata) = self.parse_rule_metadata(&rules_content, line) {
                    signatures.insert(metadata.name.clone(), metadata);
                    rule_count += 1;
                }
            }
        }

        // Add rules to compiler
        compiler.add_rules_str(&rules_content)?;

        Ok(rule_count)
    }

    /// Parse metadata from a YARA rule
    fn parse_rule_metadata(&self, content: &str, rule_line: &str) -> Option<SignatureMetadata> {
        // Extract rule name
        let rule_name = rule_line
            .trim()
            .strip_prefix("rule ")?
            .split_whitespace()
            .next()?
            .trim_end_matches('{')
            .to_string();

        // Find the metadata section for this rule
        let rule_start = content.find(rule_line)?;
        let rule_section = &content[rule_start..];
        let meta_start = rule_section.find("meta:")?;
        let meta_end = rule_section.find("strings:")
            .or_else(|| rule_section.find("condition:"))
            .unwrap_or(rule_section.len());
        
        let meta_section = &rule_section[meta_start..meta_end];

        // Parse metadata fields
        let mut threat_type = ThreatType::Unknown;
        let mut severity = ThreatSeverity::Medium;
        let mut description = String::new();
        let mut author = "Unknown".to_string();
        let mut version = "1.0".to_string();
        let mut tags = Vec::new();
        let mut references = Vec::new();

        for line in meta_section.lines() {
            let line = line.trim();
            if let Some((key, value)) = self.parse_meta_line(line) {
                match key.as_str() {
                    "description" => description = value,
                    "author" => author = value,
                    "version" => version = value,
                    "threat_type" => threat_type = self.parse_threat_type(&value),
                    "severity" => severity = self.parse_severity(&value),
                    "tags" => tags = value.split(',').map(|s| s.trim().to_string()).collect(),
                    "reference" => references.push(value),
                    _ => {}
                }
            }
        }

        Some(SignatureMetadata {
            name: rule_name,
            threat_type,
            severity,
            description,
            author,
            date: Utc::now(),
            version,
            tags,
            references,
        })
    }

    /// Parse a metadata line (key = "value")
    fn parse_meta_line(&self, line: &str) -> Option<(String, String)> {
        let parts: Vec<&str> = line.splitn(2, '=').collect();
        if parts.len() != 2 {
            return None;
        }

        let key = parts[0].trim().to_string();
        let value = parts[1].trim().trim_matches('"').to_string();
        Some((key, value))
    }

    /// Parse threat type from string
    fn parse_threat_type(&self, value: &str) -> ThreatType {
        match value.to_lowercase().as_str() {
            "virus" => ThreatType::Virus,
            "trojan" => ThreatType::Trojan,
            "rootkit" => ThreatType::Rootkit,
            "spyware" => ThreatType::Spyware,
            "adware" => ThreatType::Adware,
            "ransomware" => ThreatType::Ransomware,
            "suspicious" => ThreatType::Suspicious,
            _ => ThreatType::Unknown,
        }
    }

    /// Parse severity from string
    fn parse_severity(&self, value: &str) -> ThreatSeverity {
        match value.to_lowercase().as_str() {
            "low" => ThreatSeverity::Low,
            "medium" => ThreatSeverity::Medium,
            "high" => ThreatSeverity::High,
            "critical" => ThreatSeverity::Critical,
            _ => ThreatSeverity::Medium,
        }
    }

    /// Scan data for signature matches
    pub fn scan_data(&self, data: &[u8]) -> Result<Vec<SignatureMatch>> {
        let rules_lock = self.rules.read().unwrap();
        let rules = rules_lock.as_ref().ok_or_else(|| {
            crate::AntivirusError::ScanEngine(
                crate::ScanEngineError::SignatureDatabaseNotLoaded
            )
        })?;

        let scan_results = rules.scan_mem(data, 30)?; // 30 second timeout
        let mut matches = Vec::new();

        for result in scan_results {
            if let Some(metadata) = self.get_signature_metadata(&result.identifier) {
                let match_instances = result.strings.iter().map(|string_match| {
                    MatchInstance {
                        offset: string_match.offset,
                        length: string_match.length,
                        matched_data: string_match.data.clone(),
                        string_identifier: Some(string_match.identifier.clone()),
                    }
                }).collect();

                matches.push(SignatureMatch {
                    rule_name: result.identifier.clone(),
                    metadata: metadata.clone(),
                    matches: match_instances,
                });
            }
        }

        Ok(matches)
    }

    /// Scan a file for signature matches
    pub fn scan_file(&self, file_path: &Path) -> Result<Vec<SignatureMatch>> {
        let rules_lock = self.rules.read().unwrap();
        let rules = rules_lock.as_ref().ok_or_else(|| {
            crate::AntivirusError::ScanEngine(
                crate::ScanEngineError::SignatureDatabaseNotLoaded
            )
        })?;

        let scan_results = rules.scan_file(file_path, 30)?; // 30 second timeout
        let mut matches = Vec::new();

        for result in scan_results {
            if let Some(metadata) = self.get_signature_metadata(&result.identifier) {
                let match_instances = result.strings.iter().map(|string_match| {
                    MatchInstance {
                        offset: string_match.offset,
                        length: string_match.length,
                        matched_data: string_match.data.clone(),
                        string_identifier: Some(string_match.identifier.clone()),
                    }
                }).collect();

                matches.push(SignatureMatch {
                    rule_name: result.identifier.clone(),
                    metadata: metadata.clone(),
                    matches: match_instances,
                });
            }
        }

        Ok(matches)
    }

    /// Get signature metadata by rule name
    fn get_signature_metadata(&self, rule_name: &str) -> Option<SignatureMetadata> {
        let signatures_lock = self.signatures.read().unwrap();
        signatures_lock.get(rule_name).cloned()
    }

    /// Convert signature matches to threat info
    pub fn matches_to_threats(&self, matches: Vec<SignatureMatch>, file_path: &Path) -> Result<Vec<ThreatInfo>> {
        let mut threats = Vec::new();
        let file_hash = self.calculate_file_hash(file_path)?;

        for signature_match in matches {
            let threat = ThreatInfo::new(
                signature_match.metadata.name.clone(),
                signature_match.metadata.threat_type.clone(),
                signature_match.metadata.severity.clone(),
                file_path.to_path_buf(),
                file_hash.clone(),
                DetectionMethod::Signature,
            )?;

            threats.push(threat);
        }

        Ok(threats)
    }

    /// Calculate SHA-256 hash of a file
    fn calculate_file_hash(&self, file_path: &Path) -> Result<String> {
        use sha2::{Sha256, Digest};
        
        let data = std::fs::read(file_path)?;
        let mut hasher = Sha256::new();
        hasher.update(&data);
        let hash = hasher.finalize();
        
        Ok(format!("{:x}", hash))
    }

    /// Get database statistics
    pub fn get_statistics(&self) -> DatabaseStatistics {
        let signatures_lock = self.signatures.read().unwrap();
        let version_lock = self.version.read().unwrap();
        let last_update_lock = self.last_update.read().unwrap();

        let mut threat_type_counts = HashMap::new();
        let mut severity_counts = HashMap::new();

        for metadata in signatures_lock.values() {
            *threat_type_counts.entry(metadata.threat_type.clone()).or_insert(0) += 1;
            *severity_counts.entry(metadata.severity.clone()).or_insert(0) += 1;
        }

        DatabaseStatistics {
            total_signatures: signatures_lock.len() as u32,
            version: version_lock.clone(),
            last_update: *last_update_lock,
            threat_type_distribution: threat_type_counts,
            severity_distribution: severity_counts,
            memory_usage_bytes: self.estimate_memory_usage(),
        }
    }

    /// Estimate memory usage of the database
    fn estimate_memory_usage(&self) -> u64 {
        let signatures_lock = self.signatures.read().unwrap();
        let base_size = std::mem::size_of::<SignatureDatabase>() as u64;
        let signatures_size = signatures_lock.len() as u64 * 1024; // Rough estimate
        base_size + signatures_size
    }

    /// Update database version
    pub fn set_version(&self, version: String) {
        let mut version_lock = self.version.write().unwrap();
        *version_lock = version;
    }

    /// Get database version
    pub fn get_version(&self) -> String {
        let version_lock = self.version.read().unwrap();
        version_lock.clone()
    }

    /// Check if database is loaded
    pub fn is_loaded(&self) -> bool {
        let rules_lock = self.rules.read().unwrap();
        rules_lock.is_some()
    }

    /// Reload database from disk
    pub fn reload(&self) -> Result<CompilationStats> {
        // Find all .yar files in the database directory
        let mut rules_files = Vec::new();
        
        if self.database_path.is_dir() {
            for entry in std::fs::read_dir(&self.database_path)? {
                let entry = entry?;
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) == Some("yar") {
                    rules_files.push(path);
                }
            }
        } else if self.database_path.extension().and_then(|s| s.to_str()) == Some("yar") {
            rules_files.push(self.database_path.clone());
        }

        self.load_signatures(&rules_files)
    }
}

/// Database statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseStatistics {
    pub total_signatures: u32,
    pub version: String,
    pub last_update: Option<DateTime<Utc>>,
    pub threat_type_distribution: HashMap<ThreatType, u32>,
    pub severity_distribution: HashMap<ThreatSeverity, u32>,
    pub memory_usage_bytes: u64,
}

/// Convert YARA errors to our error type
impl From<YaraError> for crate::AntivirusError {
    fn from(error: YaraError) -> Self {
        crate::AntivirusError::ScanEngine(
            crate::ScanEngineError::YaraEngine(error.to_string())
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use std::fs;

    fn create_test_yara_rule() -> String {
        r#"
rule TestMalware
{
    meta:
        description = "Test malware signature"
        author = "Test Author"
        version = "1.0"
        threat_type = "virus"
        severity = "high"
        tags = "test,malware"
        reference = "https://example.com/malware"

    strings:
        $hex_string = { 4D 5A 90 00 }
        $text_string = "MALWARE"

    condition:
        $hex_string at 0 or $text_string
}

rule TestAdware
{
    meta:
        description = "Test adware signature"
        author = "Test Author"
        version = "1.0"
        threat_type = "adware"
        severity = "low"

    strings:
        $adware_string = "ADWARE_SIGNATURE"

    condition:
        $adware_string
}
"#.to_string()
    }

    #[test]
    fn test_signature_database_creation() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("signatures.yar");
        
        let db = SignatureDatabase::new(db_path);
        assert!(!db.is_loaded());
        assert_eq!(db.get_version(), "0.0.0");
    }

    #[test]
    fn test_load_signatures() {
        let temp_dir = TempDir::new().unwrap();
        let rules_file = temp_dir.path().join("test.yar");
        
        // Write test YARA rule
        fs::write(&rules_file, create_test_yara_rule()).unwrap();
        
        let db = SignatureDatabase::new(rules_file.clone());
        let stats = db.load_signatures(&[rules_file]).unwrap();
        
        assert!(db.is_loaded());
        assert_eq!(stats.total_rules, 2);
        assert_eq!(stats.compiled_rules, 2);
        assert_eq!(stats.failed_rules, 0);
    }

    #[test]
    fn test_scan_data() {
        let temp_dir = TempDir::new().unwrap();
        let rules_file = temp_dir.path().join("test.yar");
        
        // Write test YARA rule
        fs::write(&rules_file, create_test_yara_rule()).unwrap();
        
        let db = SignatureDatabase::new(rules_file.clone());
        db.load_signatures(&[rules_file]).unwrap();
        
        // Test data that should match
        let test_data = b"MALWARE test data";
        let matches = db.scan_data(test_data).unwrap();
        
        assert!(!matches.is_empty());
        assert_eq!(matches[0].rule_name, "TestMalware");
        assert_eq!(matches[0].metadata.threat_type, ThreatType::Virus);
        assert_eq!(matches[0].metadata.severity, ThreatSeverity::High);
    }

    #[test]
    fn test_scan_file() {
        let temp_dir = TempDir::new().unwrap();
        let rules_file = temp_dir.path().join("test.yar");
        let test_file = temp_dir.path().join("malware.exe");
        
        // Write test YARA rule
        fs::write(&rules_file, create_test_yara_rule()).unwrap();
        
        // Write test file with malware signature
        fs::write(&test_file, b"MALWARE test file content").unwrap();
        
        let db = SignatureDatabase::new(rules_file.clone());
        db.load_signatures(&[rules_file]).unwrap();
        
        let matches = db.scan_file(&test_file).unwrap();
        
        assert!(!matches.is_empty());
        assert_eq!(matches[0].rule_name, "TestMalware");
    }

    #[test]
    fn test_matches_to_threats() {
        let temp_dir = TempDir::new().unwrap();
        let rules_file = temp_dir.path().join("test.yar");
        let test_file = temp_dir.path().join("malware.exe");
        
        // Write test YARA rule
        fs::write(&rules_file, create_test_yara_rule()).unwrap();
        
        // Write test file
        fs::write(&test_file, b"MALWARE test file content").unwrap();
        
        let db = SignatureDatabase::new(rules_file.clone());
        db.load_signatures(&[rules_file]).unwrap();
        
        let matches = db.scan_file(&test_file).unwrap();
        let threats = db.matches_to_threats(matches, &test_file).unwrap();
        
        assert!(!threats.is_empty());
        assert_eq!(threats[0].name, "TestMalware");
        assert_eq!(threats[0].threat_type, ThreatType::Virus);
        assert_eq!(threats[0].severity, ThreatSeverity::High);
        assert_eq!(threats[0].detection_method, DetectionMethod::Signature);
    }

    #[test]
    fn test_database_statistics() {
        let temp_dir = TempDir::new().unwrap();
        let rules_file = temp_dir.path().join("test.yar");
        
        // Write test YARA rule
        fs::write(&rules_file, create_test_yara_rule()).unwrap();
        
        let db = SignatureDatabase::new(rules_file.clone());
        db.load_signatures(&[rules_file]).unwrap();
        
        let stats = db.get_statistics();
        
        assert_eq!(stats.total_signatures, 2);
        assert!(stats.last_update.is_some());
        assert_eq!(stats.threat_type_distribution.get(&ThreatType::Virus), Some(&1));
        assert_eq!(stats.threat_type_distribution.get(&ThreatType::Adware), Some(&1));
        assert_eq!(stats.severity_distribution.get(&ThreatSeverity::High), Some(&1));
        assert_eq!(stats.severity_distribution.get(&ThreatSeverity::Low), Some(&1));
    }

    #[test]
    fn test_metadata_parsing() {
        let temp_dir = TempDir::new().unwrap();
        let rules_file = temp_dir.path().join("test.yar");
        
        // Write test YARA rule
        fs::write(&rules_file, create_test_yara_rule()).unwrap();
        
        let db = SignatureDatabase::new(rules_file.clone());
        db.load_signatures(&[rules_file]).unwrap();
        
        let signatures_lock = db.signatures.read().unwrap();
        let malware_meta = signatures_lock.get("TestMalware").unwrap();
        
        assert_eq!(malware_meta.description, "Test malware signature");
        assert_eq!(malware_meta.author, "Test Author");
        assert_eq!(malware_meta.version, "1.0");
        assert_eq!(malware_meta.threat_type, ThreatType::Virus);
        assert_eq!(malware_meta.severity, ThreatSeverity::High);
        assert_eq!(malware_meta.tags, vec!["test", "malware"]);
        assert_eq!(malware_meta.references, vec!["https://example.com/malware"]);
    }
}