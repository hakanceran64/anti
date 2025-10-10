use async_trait::async_trait;
use std::path::{Path, PathBuf};
use std::collections::HashMap;
use tokio::fs;
use tokio::io::AsyncReadExt;
use tracing::{debug, info, warn, error};
// use chrono::Utc;
use uuid::Uuid;

use crate::{
    Result, AntivirusError, 
    types::{ScanResult, ThreatInfo, ThreatType, ThreatSeverity, DetectionMethod, ScanJobId, ScanStatus},
    traits::Scanner
};

/// Cross-platform file scanner implementation
#[derive(Debug)]
pub struct FileScanner {
    config: FileScanConfig,
    signature_db: SignatureDatabase,
    heuristic_engine: HeuristicEngine,
    scan_stats: FileScanStatistics,
}

/// File scanner configuration
#[derive(Debug, Clone)]
pub struct FileScanConfig {
    pub max_file_size_mb: u64,
    pub scan_timeout_seconds: u32,
    pub scan_archives: bool,
    pub scan_hidden_files: bool,
    pub follow_symlinks: bool,
    pub heuristic_level: u8,
    pub excluded_extensions: Vec<String>,
    pub excluded_paths: Vec<PathBuf>,
}

impl Default for FileScanConfig {
    fn default() -> Self {
        Self {
            max_file_size_mb: 100,
            scan_timeout_seconds: 30,
            scan_archives: true,
            scan_hidden_files: true,
            follow_symlinks: false,
            heuristic_level: 2,
            excluded_extensions: vec![
                "log".to_string(),
                "tmp".to_string(),
                "cache".to_string(),
            ],
            excluded_paths: vec![
                PathBuf::from("/proc"),
                PathBuf::from("/sys"),
                PathBuf::from("/dev"),
                PathBuf::from("/tmp"),
            ],
        }
    }
}

/// Simple signature database for malware detection
#[derive(Debug)]
pub struct SignatureDatabase {
    signatures: HashMap<String, MalwareSignature>,
}

/// Malware signature definition
#[derive(Debug, Clone)]
pub struct MalwareSignature {
    pub name: String,
    pub pattern: Vec<u8>,
    pub threat_type: ThreatType,
    pub severity: ThreatSeverity,
    pub description: String,
}

/// Heuristic analysis engine
#[derive(Debug)]
pub struct HeuristicEngine {
    level: u8,
}

/// File scan statistics
#[derive(Debug, Default)]
pub struct FileScanStatistics {
    pub files_scanned: u64,
    pub threats_found: u64,
    pub errors_encountered: u64,
    pub bytes_scanned: u64,
}

impl FileScanner {
    /// Create a new file scanner with default configuration
    pub fn new() -> Result<Self> {
        let config = FileScanConfig::default();
        let signature_db = SignatureDatabase::new()?;
        let heuristic_engine = HeuristicEngine::new(config.heuristic_level);
        
        Ok(Self {
            config,
            signature_db,
            heuristic_engine,
            scan_stats: FileScanStatistics::default(),
        })
    }

    /// Create a new file scanner with custom configuration
    pub fn with_config(config: FileScanConfig) -> Result<Self> {
        let signature_db = SignatureDatabase::new()?;
        let heuristic_engine = HeuristicEngine::new(config.heuristic_level);
        
        Ok(Self {
            config,
            signature_db,
            heuristic_engine,
            scan_stats: FileScanStatistics::default(),
        })
    }

    /// Scan a single file for threats
    async fn scan_file_internal(&self, path: &Path) -> Result<ScanResult> {
        let scan_id = Uuid::new_v4();
        let mut result = ScanResult::new(scan_id);
        
        debug!("Scanning file: {}", path.display());

        // Check if file should be excluded
        if self.should_exclude_file(path) {
            debug!("File excluded from scan: {}", path.display());
            result.complete();
            return Ok(result);
        }

        // Check file size
        let metadata = match fs::metadata(path).await {
            Ok(metadata) => metadata,
            Err(e) => {
                warn!("Failed to get metadata for {}: {}", path.display(), e);
                result.add_error(path.to_path_buf(), format!("Metadata error: {}", e));
                result.complete();
                return Ok(result);
            }
        };

        let file_size = metadata.len();
        let max_size = self.config.max_file_size_mb * 1024 * 1024;
        
        if file_size > max_size {
            debug!("File too large to scan: {} ({} bytes)", path.display(), file_size);
            result.complete();
            return Ok(result);
        }

        // Skip directories
        if metadata.is_dir() {
            result.complete();
            return Ok(result);
        }

        // Read file content
        let file_content = match self.read_file_safely(path, file_size).await {
            Ok(content) => content,
            Err(e) => {
                warn!("Failed to read file {}: {}", path.display(), e);
                result.add_error(path.to_path_buf(), format!("Read error: {}", e));
                result.complete();
                return Ok(result);
            }
        };

        result.scanned_files = 1;

        // Perform signature-based detection
        if let Some(threat) = self.signature_db.scan_content(&file_content, path) {
            info!("Threat detected: {} in {}", threat.name, path.display());
            result.add_threat(threat);
        }

        // Perform heuristic analysis
        if let Some(threat) = self.heuristic_engine.analyze_content(&file_content, path) {
            info!("Heuristic threat detected: {} in {}", threat.name, path.display());
            result.add_threat(threat);
        }

        result.complete();
        Ok(result)
    }

    /// Check if a file should be excluded from scanning
    fn should_exclude_file(&self, path: &Path) -> bool {
        // Check excluded paths
        for excluded_path in &self.config.excluded_paths {
            if path.starts_with(excluded_path) {
                return true;
            }
        }

        // Check excluded extensions
        if let Some(extension) = path.extension() {
            if let Some(ext_str) = extension.to_str() {
                if self.config.excluded_extensions.contains(&ext_str.to_lowercase()) {
                    return true;
                }
            }
        }

        // Check hidden files (Unix-style)
        if !self.config.scan_hidden_files {
            if let Some(filename) = path.file_name() {
                if let Some(name_str) = filename.to_str() {
                    if name_str.starts_with('.') {
                        return true;
                    }
                }
            }
        }

        false
    }

    /// Safely read file content with timeout
    async fn read_file_safely(&self, path: &Path, file_size: u64) -> Result<Vec<u8>> {
        let timeout = tokio::time::Duration::from_secs(self.config.scan_timeout_seconds as u64);
        
        let read_future = async {
            let mut file = fs::File::open(path).await?;
            let mut buffer = Vec::with_capacity(file_size as usize);
            file.read_to_end(&mut buffer).await?;
            Ok::<Vec<u8>, std::io::Error>(buffer)
        };

        match tokio::time::timeout(timeout, read_future).await {
            Ok(Ok(content)) => Ok(content),
            Ok(Err(e)) => Err(AntivirusError::Internal(format!("File read error: {}", e))),
            Err(_) => Err(AntivirusError::Internal("File read timeout".to_string())),
        }
    }

    /// Recursively scan a directory
    pub fn scan_directory<'a>(&'a self, dir_path: &'a Path) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<ScanResult>> + 'a>> {
        Box::pin(self.scan_directory_impl(dir_path))
    }

    async fn scan_directory_impl(&self, dir_path: &Path) -> Result<ScanResult> {
        let scan_id = Uuid::new_v4();
        let mut combined_result = ScanResult::new(scan_id);
        
        info!("Starting directory scan: {}", dir_path.display());

        let mut entries = match fs::read_dir(dir_path).await {
            Ok(entries) => entries,
            Err(e) => {
                error!("Failed to read directory {}: {}", dir_path.display(), e);
                combined_result.add_error(dir_path.to_path_buf(), format!("Directory read error: {}", e));
                combined_result.complete();
                return Ok(combined_result);
            }
        };

        let mut file_count = 0;
        
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            
            if path.is_dir() {
                // Skip system directories that are likely to cause permission errors
                if let Some(dir_name) = path.file_name().and_then(|n| n.to_str()) {
                    if dir_name.starts_with('.') || 
                       dir_name.contains("System Volume Information") ||
                       dir_name.contains("$RECYCLE.BIN") ||
                       dir_name.contains("Recycler") ||
                       dir_name.contains("RECYCLER") {
                        debug!("Skipping system directory: {}", path.display());
                        continue;
                    }
                }
                
                // Recursively scan subdirectories using Box::pin
                let sub_result = Box::pin(self.scan_directory_impl(&path)).await?;
                self.merge_scan_results(&mut combined_result, sub_result);
            } else {
                // Check for potentially dangerous files that MUST be scanned
                let mut must_scan = false;
                if let Some(extension) = path.extension().and_then(|e| e.to_str()) {
                    let ext_lower = extension.to_lowercase();
                    
                    // DANGEROUS files that must always be scanned
                    if matches!(ext_lower.as_str(), 
                        "exe" | "bat" | "cmd" | "com" | "scr" | "pif" | "lnk" |
                        "vbs" | "js" | "jar" | "msi" | "dll" | "sys" | "inf" |
                        "reg" | "ps1" | "hta" | "wsf" | "wsh" | "gadget"
                    ) {
                        must_scan = true;
                        info!("Found potentially dangerous file: {}", path.display());
                    }
                    // Safe files can be skipped (but still counted)
                    else if matches!(ext_lower.as_str(), 
                        "txt" | "md" | "log" | "json" | "xml" | "csv" | 
                        "jpg" | "jpeg" | "png" | "gif" | "bmp" | "tiff" |
                        "mp3" | "mp4" | "avi" | "mov" | "wav" | "flac"
                    ) {
                        file_count += 1;
                        combined_result.scanned_files += 1;
                        continue; // Skip scanning these safe file types
                    }
                }
                
                // Files without extension or unknown extensions should be scanned
                if !must_scan && path.extension().is_none() {
                    // No extension - scan it to be safe
                    must_scan = true;
                }
                
                // If we don't need to scan this file, skip it
                if !must_scan {
                    file_count += 1;
                    combined_result.scanned_files += 1;
                    continue;
                }
                
                // Check file size before scanning (skip very large files)
                if let Ok(metadata) = path.metadata() {
                    let file_size = metadata.len();
                    if file_size > 100_000_000 { // Skip files larger than 100MB
                        debug!("Skipping large file: {} ({} bytes)", path.display(), file_size);
                        file_count += 1;
                        combined_result.scanned_files += 1;
                        continue;
                    }
                }
                
                // Scan potentially risky files
                info!("Scanning potentially dangerous file: {}", path.display());
                let file_result = self.scan_file_internal(&path).await?;
                self.merge_scan_results(&mut combined_result, file_result);
                file_count += 1;
                
                // Log progress every 500 files (reduced frequency)
                if file_count % 500 == 0 {
                    info!("Scanned {} files in {}", file_count, dir_path.display());
                }
            }
        }

        combined_result.complete();
        info!("Directory scan completed: {} ({} files)", dir_path.display(), file_count);
        Ok(combined_result)
    }

    /// Merge two scan results
    fn merge_scan_results(&self, target: &mut ScanResult, source: ScanResult) {
        target.scanned_files += source.scanned_files;
        target.threats_found.extend(source.threats_found);
        target.errors.extend(source.errors);
    }

    /// Get current scan statistics
    pub fn get_statistics(&self) -> &FileScanStatistics {
        &self.scan_stats
    }

    /// Delete a threat file
    pub async fn delete_threat(&self, threat: &crate::types::ThreatInfo) -> Result<crate::types::ThreatActionResult> {
        use crate::types::{ThreatAction, ThreatActionResult};
        use chrono::Utc;
        
        info!("Attempting to delete threat file: {}", threat.file_path.display());
        
        match tokio::fs::remove_file(&threat.file_path).await {
            Ok(()) => {
                info!("Successfully deleted threat file: {}", threat.file_path.display());
                Ok(ThreatActionResult {
                    threat_id: threat.id,
                    action: ThreatAction::Delete,
                    success: true,
                    message: format!("File deleted successfully: {}", threat.file_path.display()),
                    timestamp: Utc::now(),
                })
            }
            Err(e) => {
                warn!("Failed to delete threat file {}: {}", threat.file_path.display(), e);
                Ok(ThreatActionResult {
                    threat_id: threat.id,
                    action: ThreatAction::Delete,
                    success: false,
                    message: format!("Failed to delete file: {}", e),
                    timestamp: Utc::now(),
                })
            }
        }
    }

    /// Quarantine a threat file (move to quarantine directory)
    pub async fn quarantine_threat(&self, threat: &crate::types::ThreatInfo) -> Result<crate::types::ThreatActionResult> {
        use crate::types::{ThreatAction, ThreatActionResult};
        use chrono::Utc;
        
        info!("Attempting to quarantine threat file: {}", threat.file_path.display());
        
        // Create quarantine directory if it doesn't exist
        let quarantine_dir = std::path::PathBuf::from("quarantine");
        if let Err(e) = tokio::fs::create_dir_all(&quarantine_dir).await {
            warn!("Failed to create quarantine directory: {}", e);
            return Ok(ThreatActionResult {
                threat_id: threat.id,
                action: ThreatAction::Quarantine,
                success: false,
                message: format!("Failed to create quarantine directory: {}", e),
                timestamp: Utc::now(),
            });
        }
        
        // Generate quarantine filename
        let filename = threat.file_path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");
        let quarantine_path = quarantine_dir.join(format!("{}_{}", threat.id, filename));
        
        match tokio::fs::rename(&threat.file_path, &quarantine_path).await {
            Ok(()) => {
                info!("Successfully quarantined threat file to: {}", quarantine_path.display());
                Ok(ThreatActionResult {
                    threat_id: threat.id,
                    action: ThreatAction::Quarantine,
                    success: true,
                    message: format!("File quarantined to: {}", quarantine_path.display()),
                    timestamp: Utc::now(),
                })
            }
            Err(e) => {
                warn!("Failed to quarantine threat file {}: {}", threat.file_path.display(), e);
                Ok(ThreatActionResult {
                    threat_id: threat.id,
                    action: ThreatAction::Quarantine,
                    success: false,
                    message: format!("Failed to quarantine file: {}", e),
                    timestamp: Utc::now(),
                })
            }
        }
    }

    /// Get recommended action for a threat based on its properties
    pub fn get_recommended_action(&self, threat: &crate::types::ThreatInfo) -> crate::types::ThreatAction {
        use crate::types::{ThreatAction, ThreatSeverity, ThreatType};
        
        // High-risk extensions should be deleted immediately
        if threat.name.contains("High-Risk File Extension") {
            return ThreatAction::Delete;
        }
        
        // Critical threats should be quarantined
        if threat.severity == ThreatSeverity::Critical {
            return ThreatAction::Quarantine;
        }
        
        // Ransomware should be deleted immediately
        if threat.threat_type == ThreatType::Ransomware {
            return ThreatAction::Delete;
        }
        
        // High severity threats should be quarantined
        if threat.severity == ThreatSeverity::High {
            return ThreatAction::Quarantine;
        }
        
        // Medium-risk extensions can be quarantined
        if threat.name.contains("Medium-Risk File Extension") {
            return ThreatAction::Quarantine;
        }
        
        // Default action for other threats
        match threat.severity {
            ThreatSeverity::Medium => ThreatAction::Quarantine,
            ThreatSeverity::Low => ThreatAction::Ignore,
            _ => ThreatAction::Quarantine,
        }
    }
}

#[async_trait]
impl Scanner for FileScanner {
    async fn scan_file(&self, path: &Path) -> Result<ScanResult> {
        self.scan_file_internal(path).await
    }

    async fn scan_memory(&self, _process_id: u32) -> Result<ScanResult> {
        // Memory scanning not implemented for file scanner
        let scan_id = Uuid::new_v4();
        let mut result = ScanResult::new(scan_id);
        result.complete();
        Ok(result)
    }

    async fn scan_network_packet(&self, _packet: &crate::NetworkPacket) -> Result<ScanResult> {
        // Network packet scanning not implemented for file scanner
        let scan_id = Uuid::new_v4();
        let mut result = ScanResult::new(scan_id);
        result.complete();
        Ok(result)
    }

    async fn start_scan(&self, scan_type: crate::types::ScanType, _targets: Vec<PathBuf>) -> Result<ScanJobId> {
        let job_id = Uuid::new_v4();
        info!("Starting scan job {} with type {:?}", job_id, scan_type);
        
        // In a real implementation, this would start a background task
        // For now, we'll just return the job ID
        Ok(job_id)
    }

    async fn get_scan_status(&self, _job_id: ScanJobId) -> Result<ScanStatus> {
        // In a real implementation, this would track actual scan status
        Ok(ScanStatus::Completed)
    }

    async fn cancel_scan(&self, job_id: ScanJobId) -> Result<()> {
        info!("Cancelling scan job {}", job_id);
        // In a real implementation, this would cancel the background task
        Ok(())
    }
}

impl SignatureDatabase {
    /// Create a new signature database with default signatures
    pub fn new() -> Result<Self> {
        let mut signatures = HashMap::new();
        
        // Add some example malware signatures
        signatures.insert("eicar".to_string(), MalwareSignature {
            name: "EICAR Test String".to_string(),
            pattern: b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*".to_vec(),
            threat_type: ThreatType::Virus,
            severity: ThreatSeverity::High,
            description: "EICAR antivirus test file".to_string(),
        });

        // Only flag executables with PE header as suspicious, not all files
        signatures.insert("suspicious_exe".to_string(), MalwareSignature {
            name: "Suspicious Executable".to_string(),
            pattern: b"MZ".to_vec(), // PE header
            threat_type: ThreatType::Suspicious,
            severity: ThreatSeverity::Low,
            description: "Potentially suspicious executable file".to_string(),
        });

        // Add more sophisticated patterns
        signatures.insert("powershell_encoded".to_string(), MalwareSignature {
            name: "Encoded PowerShell".to_string(),
            pattern: b"powershell -EncodedCommand".to_vec(),
            threat_type: ThreatType::Suspicious,
            severity: ThreatSeverity::Medium,
            description: "Encoded PowerShell command detected".to_string(),
        });

        Ok(Self { signatures })
    }

    /// Scan content for known malware signatures
    pub fn scan_content(&self, content: &[u8], path: &Path) -> Option<ThreatInfo> {
        // First check if file extension should be treated differently
        if let Some(extension_threat) = self.check_extension_based_threat(path) {
            return Some(extension_threat);
        }

        // Skip PE header check for known safe file types
        if self.is_safe_file_type(path) {
            // Only check for specific malware signatures, not generic PE header
            for (sig_id, signature) in &self.signatures {
                if sig_id == "suspicious_exe" {
                    continue; // Skip PE header check for safe files
                }
                
                if self.contains_pattern(content, &signature.pattern) {
                    debug!("Signature match: {} in {}", sig_id, path.display());
                    
                    if let Ok(threat) = ThreatInfo::new(
                        signature.name.clone(),
                        signature.threat_type.clone(),
                        signature.severity.clone(),
                        path.to_path_buf(),
                        self.calculate_file_hash(content),
                        DetectionMethod::Signature,
                    ) {
                        return Some(threat);
                    }
                }
            }
            return None;
        }

        // For other files, check all signatures
        for (sig_id, signature) in &self.signatures {
            if self.contains_pattern(content, &signature.pattern) {
                debug!("Signature match: {} in {}", sig_id, path.display());
                
                if let Ok(threat) = ThreatInfo::new(
                    signature.name.clone(),
                    signature.threat_type.clone(),
                    signature.severity.clone(),
                    path.to_path_buf(),
                    self.calculate_file_hash(content),
                    DetectionMethod::Signature,
                ) {
                    return Some(threat);
                }
            }
        }
        None
    }

    /// Check for extension-based threats
    fn check_extension_based_threat(&self, path: &Path) -> Option<ThreatInfo> {
        if let Some(extension) = path.extension() {
            if let Some(ext_str) = extension.to_str() {
                let ext_lower = ext_str.to_lowercase();
                
                // High-risk extensions
                let high_risk_extensions = [
                    "vbs", "vbe", "js", "jse", "wsf", "wsh", "scr", "pif", "com", "bat", "cmd",
                    "reg", "msi", "hta", "cpl", "jar", "ps1", "psm1", "psd1", "ps1xml",
                ];
                
                // Medium-risk extensions
                let medium_risk_extensions = [
                    "lnk", "url", "scf", "inf", "dat", "tmp", "dmp",
                ];
                
                if high_risk_extensions.contains(&ext_lower.as_str()) {
                    return ThreatInfo::new(
                        format!("High-Risk File Extension: .{}", ext_lower),
                        ThreatType::Suspicious,
                        ThreatSeverity::High,
                        path.to_path_buf(),
                        self.calculate_file_hash(&[]), // Empty hash for extension-based detection
                        DetectionMethod::Heuristic,
                    ).ok();
                }
                
                if medium_risk_extensions.contains(&ext_lower.as_str()) {
                    return ThreatInfo::new(
                        format!("Medium-Risk File Extension: .{}", ext_lower),
                        ThreatType::Suspicious,
                        ThreatSeverity::Medium,
                        path.to_path_buf(),
                        self.calculate_file_hash(&[]), // Empty hash for extension-based detection
                        DetectionMethod::Heuristic,
                    ).ok();
                }
            }
        }
        None
    }

    /// Check if file type is considered safe
    fn is_safe_file_type(&self, path: &Path) -> bool {
        if let Some(extension) = path.extension() {
            if let Some(ext_str) = extension.to_str() {
                let ext_lower = ext_str.to_lowercase();
                
                // Safe file extensions
                let safe_extensions = [
                    // Documents
                    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "odt", "ods", "odp",
                    "rtf", "txt", "csv",
                    
                    // Images
                    "jpg", "jpeg", "png", "gif", "bmp", "tiff", "tif", "webp", "svg", "ico",
                    
                    // Audio
                    "mp3", "wav", "flac", "aac", "ogg", "wma", "m4a",
                    
                    // Video
                    "mp4", "avi", "mkv", "mov", "wmv", "flv", "webm", "m4v",
                    
                    // Archives (with caution)
                    "zip", "rar", "7z", "tar", "gz", "bz2",
                    
                    // Development (safe in most contexts)
                    "json", "xml", "yaml", "yml", "toml", "ini", "cfg", "conf",
                    "md", "rst", "log",
                ];
                
                return safe_extensions.contains(&ext_lower.as_str());
            }
        }
        false
    }

    /// Check if content contains a specific pattern
    fn contains_pattern(&self, content: &[u8], pattern: &[u8]) -> bool {
        if pattern.is_empty() || content.len() < pattern.len() {
            return false;
        }

        content.windows(pattern.len()).any(|window| window == pattern)
    }

    /// Calculate SHA-256 hash of file content
    fn calculate_file_hash(&self, content: &[u8]) -> String {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(content);
        format!("{:x}", hasher.finalize())
    }
}

impl HeuristicEngine {
    /// Create a new heuristic engine
    pub fn new(level: u8) -> Self {
        Self { level }
    }

    /// Analyze content using heuristic methods
    pub fn analyze_content(&self, content: &[u8], path: &Path) -> Option<ThreatInfo> {
        if self.level == 0 {
            return None;
        }

        let mut suspicion_score = 0;
        let mut threat_indicators = Vec::new();

        // Check for high entropy (packed/encrypted files)
        let entropy = self.calculate_entropy(content);
        if entropy > 7.5 {
            suspicion_score += 30;
            threat_indicators.push("High entropy content".to_string());
        }

        // Check for suspicious strings
        let suspicious_strings = [
            "CreateRemoteThread",
            "VirtualAllocEx",
            "WriteProcessMemory", 
            "SetWindowsHookEx",
            "keylogger",
            "password",
            "bitcoin",
            "cryptocurrency",
        ];

        for pattern in &suspicious_strings {
            let pattern_bytes = pattern.as_bytes();
            if content.windows(pattern_bytes.len()).any(|window| window == pattern_bytes) {
                suspicion_score += 10;
                threat_indicators.push(format!("Suspicious string: {}", pattern));
            }
        }

        // Check file extension vs content mismatch
        if let Some(extension) = path.extension() {
            if let Some(ext_str) = extension.to_str() {
                if self.check_extension_mismatch(content, ext_str) {
                    suspicion_score += 20;
                    threat_indicators.push("File extension mismatch".to_string());
                }
            }
        }

        // Determine if file is suspicious based on score and level
        let threshold = match self.level {
            1 => 60,  // Low sensitivity
            2 => 40,  // Medium sensitivity
            3 => 20,  // High sensitivity
            _ => 40,
        };

        if suspicion_score >= threshold {
            if let Ok(threat) = ThreatInfo::new(
                "Heuristic Detection".to_string(),
                ThreatType::Suspicious,
                if suspicion_score > 60 { ThreatSeverity::High } else { ThreatSeverity::Medium },
                path.to_path_buf(),
                self.calculate_file_hash(content),
                DetectionMethod::Heuristic,
            ) {
                return Some(threat);
            }
        }

        None
    }

    /// Calculate Shannon entropy of content
    fn calculate_entropy(&self, data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }

        let mut counts = [0u32; 256];
        for &byte in data {
            counts[byte as usize] += 1;
        }

        let len = data.len() as f64;
        let mut entropy = 0.0;

        for count in counts.iter() {
            if *count > 0 {
                let p = *count as f64 / len;
                entropy -= p * p.log2();
            }
        }

        entropy
    }

    /// Check for file extension vs content mismatch
    fn check_extension_mismatch(&self, content: &[u8], extension: &str) -> bool {
        if content.len() < 4 {
            return false;
        }

        let header = &content[0..4];
        
        match extension.to_lowercase().as_str() {
            "txt" | "log" => {
                // Text files shouldn't start with binary headers
                header.starts_with(b"MZ") || header.starts_with(b"\x7fELF")
            }
            "jpg" | "jpeg" => {
                // JPEG files should start with FF D8
                !header.starts_with(&[0xFF, 0xD8])
            }
            "png" => {
                // PNG files should start with PNG signature
                !header.starts_with(&[0x89, 0x50, 0x4E, 0x47])
            }
            "pdf" => {
                // PDF files should start with %PDF
                !header.starts_with(b"%PDF")
            }
            _ => false,
        }
    }

    /// Calculate SHA-256 hash of file content
    fn calculate_file_hash(&self, content: &[u8]) -> String {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(content);
        format!("{:x}", hasher.finalize())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn test_file_scanner_creation() {
        let scanner = FileScanner::new();
        assert!(scanner.is_ok());
    }

    #[tokio::test]
    async fn test_eicar_detection() {
        let scanner = FileScanner::new().unwrap();
        
        // Create temporary file with EICAR test string
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*").unwrap();
        
        let result = scanner.scan_file(temp_file.path()).await.unwrap();
        assert!(!result.threats_found.is_empty());
        assert_eq!(result.threats_found[0].name, "EICAR Test String");
    }

    #[tokio::test]
    async fn test_clean_file() {
        let scanner = FileScanner::new().unwrap();
        
        // Create temporary file with clean content
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"This is a clean test file with no threats.").unwrap();
        
        let result = scanner.scan_file(temp_file.path()).await.unwrap();
        assert!(result.threats_found.is_empty());
    }

    #[tokio::test]
    async fn test_heuristic_detection() {
        let scanner = FileScanner::with_config(FileScanConfig {
            heuristic_level: 3, // High sensitivity
            ..Default::default()
        }).unwrap();
        
        // Create file with suspicious content
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"CreateRemoteThread VirtualAllocEx WriteProcessMemory keylogger password").unwrap();
        
        let result = scanner.scan_file(temp_file.path()).await.unwrap();
        // Should detect as suspicious due to multiple suspicious strings
        assert!(!result.threats_found.is_empty());
    }

    #[tokio::test]
    async fn test_entropy_calculation() {
        let engine = HeuristicEngine::new(2);
        
        // Low entropy content (repeated characters)
        let low_entropy = vec![b'A'; 1000];
        let entropy1 = engine.calculate_entropy(&low_entropy);
        assert!(entropy1 < 1.0);
        
        // High entropy content (random-like)
        let high_entropy: Vec<u8> = (0..=255).cycle().take(1000).collect();
        let entropy2 = engine.calculate_entropy(&high_entropy);
        assert!(entropy2 > 7.0);
    }
}