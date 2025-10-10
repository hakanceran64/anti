use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use uuid::Uuid;
use crate::Result;

// Core ID types
pub type ThreatId = Uuid;
pub type ScanId = Uuid;
pub type QuarantineId = Uuid;
pub type SandboxId = Uuid;
pub type ScanJobId = Uuid;

/// Threat information structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatInfo {
    pub id: ThreatId,
    pub name: String,
    pub threat_type: ThreatType,
    pub severity: ThreatSeverity,
    pub file_path: PathBuf,
    pub file_hash: String,
    pub detection_method: DetectionMethod,
    pub timestamp: DateTime<Utc>,
    pub additional_info: HashMap<String, String>,
}

impl ThreatInfo {
    /// Create a new ThreatInfo with validation
    pub fn new(
        name: String,
        threat_type: ThreatType,
        severity: ThreatSeverity,
        file_path: PathBuf,
        file_hash: String,
        detection_method: DetectionMethod,
    ) -> Result<Self> {
        // Validate threat name
        if name.trim().is_empty() {
            return Err(crate::AntivirusError::Internal(
                "Threat name cannot be empty".to_string()
            ));
        }

        // Validate file hash (should be SHA-256 hex string)
        if !Self::is_valid_hash(&file_hash) {
            return Err(crate::AntivirusError::Internal(
                "Invalid file hash format".to_string()
            ));
        }

        // Validate file path exists (optional check)
        if !file_path.exists() {
            tracing::warn!("Threat detected in non-existent file: {}", file_path.display());
        }

        Ok(Self {
            id: Uuid::new_v4(),
            name: name.trim().to_string(),
            threat_type,
            severity,
            file_path,
            file_hash: file_hash.to_lowercase(),
            detection_method,
            timestamp: Utc::now(),
            additional_info: HashMap::new(),
        })
    }

    /// Validate hash format (SHA-256 hex string)
    fn is_valid_hash(hash: &str) -> bool {
        hash.len() == 64 && hash.chars().all(|c| c.is_ascii_hexdigit())
    }

    /// Add additional information
    pub fn add_info(&mut self, key: String, value: String) {
        self.additional_info.insert(key, value);
    }

    /// Get threat risk score based on severity and type
    pub fn get_risk_score(&self) -> u8 {
        let severity_score = match self.severity {
            ThreatSeverity::Low => 25,
            ThreatSeverity::Medium => 50,
            ThreatSeverity::High => 75,
            ThreatSeverity::Critical => 100,
        };

        let type_modifier = match self.threat_type {
            ThreatType::Ransomware => 20,
            ThreatType::Rootkit => 15,
            ThreatType::Trojan => 10,
            ThreatType::Virus => 5,
            ThreatType::Spyware => 5,
            ThreatType::Adware => -10,
            ThreatType::Suspicious => -5,
            ThreatType::Unknown => 0,
        };

        (severity_score + type_modifier).clamp(0, 100) as u8
    }

    /// Check if threat requires immediate action
    pub fn requires_immediate_action(&self) -> bool {
        matches!(self.severity, ThreatSeverity::Critical | ThreatSeverity::High) ||
        matches!(self.threat_type, ThreatType::Ransomware | ThreatType::Rootkit)
    }
}

/// Types of threats that can be detected
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ThreatType {
    Virus,
    Trojan,
    Rootkit,
    Spyware,
    Adware,
    Ransomware,
    Suspicious,
    Unknown,
}

/// Severity levels for threats
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ThreatSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl ThreatSeverity {
    /// Get numeric value for comparison
    pub fn to_numeric(&self) -> u8 {
        match self {
            ThreatSeverity::Low => 1,
            ThreatSeverity::Medium => 2,
            ThreatSeverity::High => 3,
            ThreatSeverity::Critical => 4,
        }
    }

    /// Create from numeric value
    pub fn from_numeric(value: u8) -> Option<Self> {
        match value {
            1 => Some(ThreatSeverity::Low),
            2 => Some(ThreatSeverity::Medium),
            3 => Some(ThreatSeverity::High),
            4 => Some(ThreatSeverity::Critical),
            _ => None,
        }
    }

    /// Get color representation for UI
    pub fn get_color_code(&self) -> &'static str {
        match self {
            ThreatSeverity::Low => "#28a745",      // Green
            ThreatSeverity::Medium => "#ffc107",   // Yellow
            ThreatSeverity::High => "#fd7e14",     // Orange
            ThreatSeverity::Critical => "#dc3545", // Red
        }
    }
}

/// Methods used to detect threats
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum DetectionMethod {
    Signature,
    Heuristic,
    MachineLearning,
    Behavioral,
    Sandbox,
    Static,
    Dynamic,
}

/// Actions that can be taken on threats
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ThreatAction {
    Ignore,
    Quarantine,
    Delete,
    Clean,
    Block,
}

/// Result of a threat action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatActionResult {
    pub threat_id: ThreatId,
    pub action: ThreatAction,
    pub success: bool,
    pub message: String,
    pub timestamp: DateTime<Utc>,
}

/// Scan result information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub scan_id: ScanId,
    pub start_time: DateTime<Utc>,
    pub end_time: Option<DateTime<Utc>>,
    pub status: ScanStatus,
    pub scanned_files: u64,
    pub threats_found: Vec<ThreatInfo>,
    pub errors: Vec<ScanError>,
    pub statistics: ScanStatistics,
}

impl ScanResult {
    /// Create a new scan result
    pub fn new(scan_id: ScanId) -> Self {
        Self {
            scan_id,
            start_time: Utc::now(),
            end_time: None,
            status: ScanStatus::Running,
            scanned_files: 0,
            threats_found: Vec::new(),
            errors: Vec::new(),
            statistics: ScanStatistics::default(),
        }
    }

    /// Mark scan as completed
    pub fn complete(&mut self) {
        self.end_time = Some(Utc::now());
        self.status = ScanStatus::Completed;
        self.update_statistics();
    }

    /// Mark scan as failed
    pub fn fail(&mut self, error_message: String) {
        self.end_time = Some(Utc::now());
        self.status = ScanStatus::Failed;
        self.errors.push(ScanError {
            file_path: PathBuf::from("SCAN_FAILURE"),
            error_message,
            timestamp: Utc::now(),
        });
        self.update_statistics();
    }

    /// Add a threat to the results
    pub fn add_threat(&mut self, threat: ThreatInfo) {
        self.threats_found.push(threat);
        self.update_statistics();
    }

    /// Add an error to the results
    pub fn add_error(&mut self, file_path: PathBuf, error_message: String) {
        self.errors.push(ScanError {
            file_path,
            error_message,
            timestamp: Utc::now(),
        });
    }

    /// Update internal statistics
    fn update_statistics(&mut self) {
        self.statistics.infected_files = self.threats_found.len() as u64;
        self.statistics.scanned_files = self.scanned_files;
        
        if let Some(end_time) = self.end_time {
            let duration = end_time.signed_duration_since(self.start_time);
            self.statistics.scan_duration_ms = duration.num_milliseconds().max(0) as u64;
            
            if self.scanned_files > 0 {
                self.statistics.average_scan_time_ms = 
                    self.statistics.scan_duration_ms as f64 / self.scanned_files as f64;
            }
        }
    }

    /// Get scan duration in seconds
    pub fn get_duration_seconds(&self) -> Option<f64> {
        self.end_time.map(|end| {
            let duration = end.signed_duration_since(self.start_time);
            duration.num_milliseconds() as f64 / 1000.0
        })
    }

    /// Check if scan found any threats
    pub fn has_threats(&self) -> bool {
        !self.threats_found.is_empty()
    }

    /// Get threats by severity
    pub fn get_threats_by_severity(&self, severity: ThreatSeverity) -> Vec<&ThreatInfo> {
        self.threats_found.iter()
            .filter(|threat| threat.severity == severity)
            .collect()
    }

    /// Get scan success rate (files scanned without errors)
    pub fn get_success_rate(&self) -> f64 {
        if self.statistics.total_files == 0 {
            return 1.0;
        }
        
        let successful_files = self.statistics.total_files - self.errors.len() as u64;
        successful_files as f64 / self.statistics.total_files as f64
    }
}

/// Status of a scan operation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ScanStatus {
    Running,
    Completed,
    Cancelled,
    Failed,
    Paused,
}

/// Scan error information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanError {
    pub file_path: PathBuf,
    pub error_message: String,
    pub timestamp: DateTime<Utc>,
}

/// Scan statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanStatistics {
    pub total_files: u64,
    pub scanned_files: u64,
    pub skipped_files: u64,
    pub infected_files: u64,
    pub cleaned_files: u64,
    pub quarantined_files: u64,
    pub scan_duration_ms: u64,
    pub average_scan_time_ms: f64,
}

impl Default for ScanStatistics {
    fn default() -> Self {
        Self {
            total_files: 0,
            scanned_files: 0,
            skipped_files: 0,
            infected_files: 0,
            cleaned_files: 0,
            quarantined_files: 0,
            scan_duration_ms: 0,
            average_scan_time_ms: 0.0,
        }
    }
}

impl ScanStatistics {
    /// Calculate completion percentage
    pub fn completion_percentage(&self) -> f64 {
        if self.total_files == 0 {
            return 100.0;
        }
        (self.scanned_files as f64 / self.total_files as f64) * 100.0
    }

    /// Calculate infection rate
    pub fn infection_rate(&self) -> f64 {
        if self.scanned_files == 0 {
            return 0.0;
        }
        (self.infected_files as f64 / self.scanned_files as f64) * 100.0
    }

    /// Get files per second scan rate
    pub fn files_per_second(&self) -> f64 {
        if self.scan_duration_ms == 0 {
            return 0.0;
        }
        (self.scanned_files as f64 * 1000.0) / self.scan_duration_ms as f64
    }
}

/// Types of scans that can be performed
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ScanType {
    Quick,
    Full,
    Custom(Vec<PathBuf>),
    Memory,
    Startup,
}

/// Quarantine entry information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineEntry {
    pub id: QuarantineId,
    pub original_path: PathBuf,
    pub threat_info: ThreatInfo,
    pub quarantine_time: DateTime<Utc>,
    pub file_size: u64,
    pub encrypted_path: PathBuf,
}

impl QuarantineEntry {
    /// Create a new quarantine entry
    pub fn new(
        original_path: PathBuf,
        threat_info: ThreatInfo,
        file_size: u64,
        encrypted_path: PathBuf,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            original_path,
            threat_info,
            quarantine_time: Utc::now(),
            file_size,
            encrypted_path,
        }
    }

    /// Get age of quarantine entry in days
    pub fn age_in_days(&self) -> i64 {
        let now = Utc::now();
        now.signed_duration_since(self.quarantine_time).num_days()
    }

    /// Check if entry should be auto-deleted based on age
    pub fn should_auto_delete(&self, max_age_days: u32) -> bool {
        self.age_in_days() > max_age_days as i64
    }

    /// Get human-readable file size
    pub fn get_formatted_size(&self) -> String {
        const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
        let mut size = self.file_size as f64;
        let mut unit_index = 0;

        while size >= 1024.0 && unit_index < UNITS.len() - 1 {
            size /= 1024.0;
            unit_index += 1;
        }

        if unit_index == 0 {
            format!("{} {}", self.file_size, UNITS[unit_index])
        } else {
            format!("{:.2} {}", size, UNITS[unit_index])
        }
    }

    /// Get original file name
    pub fn get_file_name(&self) -> String {
        self.original_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("Unknown")
            .to_string()
    }

    /// Validate quarantine entry
    pub fn validate(&self) -> Result<()> {
        // Check if encrypted file exists
        if !self.encrypted_path.exists() {
            return Err(crate::AntivirusError::Quarantine(
                crate::QuarantineError::EntryNotFound(
                    format!("Encrypted file not found: {}", self.encrypted_path.display())
                )
            ));
        }

        // Validate file size matches
        if let Ok(metadata) = std::fs::metadata(&self.encrypted_path) {
            if metadata.len() != self.file_size {
                tracing::warn!(
                    "File size mismatch for quarantine entry {}: expected {}, found {}",
                    self.id, self.file_size, metadata.len()
                );
            }
        }

        Ok(())
    }
}

/// System status information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemStatus {
    pub realtime_protection_enabled: bool,
    pub last_scan_time: Option<DateTime<Utc>>,
    pub last_update_time: Option<DateTime<Utc>>,
    pub signature_version: String,
    pub engine_version: String,
    pub threats_detected_today: u32,
    pub quarantine_count: u32,
}

impl SystemStatus {
    /// Create a new system status
    pub fn new(engine_version: String, signature_version: String) -> Self {
        Self {
            realtime_protection_enabled: true,
            last_scan_time: None,
            last_update_time: None,
            signature_version,
            engine_version,
            threats_detected_today: 0,
            quarantine_count: 0,
        }
    }

    /// Check if system needs updates (older than 24 hours)
    pub fn needs_update(&self) -> bool {
        match self.last_update_time {
            Some(last_update) => {
                let now = Utc::now();
                let duration = now.signed_duration_since(last_update);
                duration.num_hours() > 24
            }
            None => true, // Never updated
        }
    }

    /// Check if system needs scan (older than 7 days)
    pub fn needs_scan(&self) -> bool {
        match self.last_scan_time {
            Some(last_scan) => {
                let now = Utc::now();
                let duration = now.signed_duration_since(last_scan);
                duration.num_days() > 7
            }
            None => true, // Never scanned
        }
    }

    /// Get protection status as string
    pub fn get_protection_status(&self) -> &'static str {
        if self.realtime_protection_enabled {
            "Protected"
        } else {
            "At Risk"
        }
    }

    /// Get overall health score (0-100)
    pub fn get_health_score(&self) -> u8 {
        let mut score = 100u8;

        // Deduct points for disabled real-time protection
        if !self.realtime_protection_enabled {
            score = score.saturating_sub(40);
        }

        // Deduct points for outdated updates
        if self.needs_update() {
            score = score.saturating_sub(20);
        }

        // Deduct points for not scanning recently
        if self.needs_scan() {
            score = score.saturating_sub(15);
        }

        // Deduct points for threats detected today
        if self.threats_detected_today > 0 {
            let threat_penalty = (self.threats_detected_today * 5).min(25);
            score = score.saturating_sub(threat_penalty as u8);
        }

        score
    }

    /// Get health status as string
    pub fn get_health_status(&self) -> &'static str {
        match self.get_health_score() {
            90..=100 => "Excellent",
            70..=89 => "Good",
            50..=69 => "Fair",
            30..=49 => "Poor",
            _ => "Critical",
        }
    }
}

/// Scan progress information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanProgress {
    pub scan_id: ScanId,
    pub current_file: Option<PathBuf>,
    pub files_scanned: u64,
    pub total_files: u64,
    pub threats_found: u32,
    pub percentage_complete: f32,
    pub estimated_time_remaining_ms: Option<u64>,
}

/// Antivirus configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AntivirusConfig {
    pub realtime_protection: RealtimeConfig,
    pub scan_settings: ScanConfig,
    pub quarantine_settings: QuarantineConfig,
    pub update_settings: UpdateConfig,
    pub whitelist: Vec<WhitelistEntry>,
    pub enterprise_policy: Option<EnterprisePolicy>,
}

impl Default for AntivirusConfig {
    fn default() -> Self {
        Self {
            realtime_protection: RealtimeConfig::default(),
            scan_settings: ScanConfig::default(),
            quarantine_settings: QuarantineConfig::default(),
            update_settings: UpdateConfig::default(),
            whitelist: Vec::new(),
            enterprise_policy: None,
        }
    }
}

/// Real-time protection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealtimeConfig {
    pub enabled: bool,
    pub scan_on_access: bool,
    pub scan_on_write: bool,
    pub scan_archives: bool,
    pub scan_email_attachments: bool,
    pub scan_network_drives: bool,
    pub scan_network_traffic: bool,
}

impl Default for RealtimeConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            scan_on_access: true,
            scan_on_write: true,
            scan_archives: true,
            scan_email_attachments: true,
            scan_network_drives: false,
            scan_network_traffic: true,
        }
    }
}

/// Scan configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    pub max_file_size_mb: u64,
    pub scan_timeout_seconds: u32,
    pub heuristic_level: u8,
    pub use_machine_learning: bool,
    pub scan_packed_files: bool,
    pub max_scan_depth: u32,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            max_file_size_mb: 100,
            scan_timeout_seconds: 30,
            heuristic_level: 2,
            use_machine_learning: true,
            scan_packed_files: true,
            max_scan_depth: 10,
        }
    }
}

/// Quarantine configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineConfig {
    pub max_size_gb: u64,
    pub auto_delete_days: u32,
    pub encrypt_files: bool,
    pub backup_original_permissions: bool,
}

impl Default for QuarantineConfig {
    fn default() -> Self {
        Self {
            max_size_gb: 10,
            auto_delete_days: 30,
            encrypt_files: true,
            backup_original_permissions: true,
        }
    }
}

/// Update configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateConfig {
    pub auto_update_enabled: bool,
    pub update_frequency_hours: u32,
    pub use_delta_updates: bool,
    pub update_server_url: String,
}

impl Default for UpdateConfig {
    fn default() -> Self {
        Self {
            auto_update_enabled: true,
            update_frequency_hours: 4,
            use_delta_updates: true,
            update_server_url: "https://updates.windowsantivirus.com".to_string(),
        }
    }
}

/// Whitelist entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhitelistEntry {
    pub entry_type: WhitelistEntryType,
    pub value: String,
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

/// Types of whitelist entries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WhitelistEntryType {
    FilePath,
    FileHash,
    ProcessName,
    Directory,
    Extension,
}

/// Enterprise policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnterprisePolicy {
    pub policy_version: String,
    pub policy_name: String,
    pub restrictions: PolicyRestrictions,
    pub mandatory_settings: MandatorySettings,
    pub applied_at: DateTime<Utc>,
}

/// Policy restrictions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRestrictions {
    pub allow_user_whitelist: bool,
    pub allow_disable_realtime: bool,
    pub allow_quarantine_restore: bool,
    pub require_admin_for_settings: bool,
    pub force_update_schedule: bool,
}

/// Mandatory settings enforced by policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MandatorySettings {
    pub minimum_scan_frequency_days: u32,
    pub required_protection_level: ProtectionLevel,
    pub blocked_file_types: Vec<String>,
    pub required_logging_level: LogLevel,
}

/// Protection levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProtectionLevel {
    Basic,
    Standard,
    Enhanced,
    Maximum,
}

/// Logging levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

/// Update information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateInfo {
    pub component_name: String,
    pub current_version: String,
    pub new_version: String,
    pub release_date: DateTime<Utc>,
    pub size_bytes: u64,
    pub download_url: String,
    pub signature: String,
    pub description: String,
    pub is_critical: bool,
}



/// Process information for process monitoring
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub process_id: u32,
    pub parent_process_id: u32,
    pub process_name: String,
    pub executable_path: PathBuf,
    pub command_line: String,
    pub creation_time: DateTime<Utc>,
}

/// Thread information for thread monitoring
#[derive(Debug, Clone)]
pub struct ThreadInfo {
    pub thread_id: u32,
    pub process_id: u32,
    pub creation_time: DateTime<Utc>,
}

/// Image load information for DLL monitoring
#[derive(Debug, Clone)]
pub struct ImageInfo {
    pub process_id: u32,
    pub image_path: PathBuf,
    pub base_address: u64,
    pub image_size: u64,
    pub load_time: DateTime<Utc>,
}
#[cfg
(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_threat_info_creation() {
        let threat = ThreatInfo::new(
            "Test.Malware".to_string(),
            ThreatType::Virus,
            ThreatSeverity::High,
            PathBuf::from("/tmp/test.exe"),
            "a".repeat(64), // Valid SHA-256 hash
            DetectionMethod::Signature,
        );

        assert!(threat.is_ok());
        let threat = threat.unwrap();
        assert_eq!(threat.name, "Test.Malware");
        assert_eq!(threat.threat_type, ThreatType::Virus);
        assert_eq!(threat.severity, ThreatSeverity::High);
    }

    #[test]
    fn test_threat_info_validation() {
        // Test empty name
        let result = ThreatInfo::new(
            "".to_string(),
            ThreatType::Virus,
            ThreatSeverity::Low,
            PathBuf::from("/tmp/test.exe"),
            "a".repeat(64),
            DetectionMethod::Signature,
        );
        assert!(result.is_err());

        // Test invalid hash
        let result = ThreatInfo::new(
            "Test.Malware".to_string(),
            ThreatType::Virus,
            ThreatSeverity::Low,
            PathBuf::from("/tmp/test.exe"),
            "invalid_hash".to_string(),
            DetectionMethod::Signature,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_threat_risk_score() {
        let mut threat = ThreatInfo::new(
            "Test.Ransomware".to_string(),
            ThreatType::Ransomware,
            ThreatSeverity::Critical,
            PathBuf::from("/tmp/test.exe"),
            "a".repeat(64),
            DetectionMethod::Signature,
        ).unwrap();

        // Critical ransomware should have maximum risk score
        assert_eq!(threat.get_risk_score(), 100);

        // Test requires immediate action
        assert!(threat.requires_immediate_action());

        // Test low severity adware
        threat.threat_type = ThreatType::Adware;
        threat.severity = ThreatSeverity::Low;
        assert_eq!(threat.get_risk_score(), 15); // 25 + (-10) = 15
        assert!(!threat.requires_immediate_action());
    }

    #[test]
    fn test_scan_result_lifecycle() {
        let scan_id = Uuid::new_v4();
        let mut result = ScanResult::new(scan_id);

        assert_eq!(result.scan_id, scan_id);
        assert_eq!(result.status, ScanStatus::Running);
        assert!(result.end_time.is_none());

        // Add a threat
        let threat = ThreatInfo::new(
            "Test.Virus".to_string(),
            ThreatType::Virus,
            ThreatSeverity::Medium,
            PathBuf::from("/tmp/virus.exe"),
            "b".repeat(64),
            DetectionMethod::Heuristic,
        ).unwrap();

        result.add_threat(threat);
        assert!(result.has_threats());
        assert_eq!(result.threats_found.len(), 1);

        // Complete the scan
        result.complete();
        assert_eq!(result.status, ScanStatus::Completed);
        assert!(result.end_time.is_some());
        assert!(result.get_duration_seconds().is_some());
    }

    #[test]
    fn test_scan_statistics() {
        let mut stats = ScanStatistics::default();
        assert_eq!(stats.completion_percentage(), 100.0);
        assert_eq!(stats.infection_rate(), 0.0);

        stats.total_files = 100;
        stats.scanned_files = 50;
        stats.infected_files = 5;
        stats.scan_duration_ms = 10000; // 10 seconds

        assert_eq!(stats.completion_percentage(), 50.0);
        assert_eq!(stats.infection_rate(), 10.0);
        assert_eq!(stats.files_per_second(), 5.0);
    }

    #[test]
    fn test_threat_severity_ordering() {
        assert!(ThreatSeverity::Critical.to_numeric() > ThreatSeverity::High.to_numeric());
        assert!(ThreatSeverity::High.to_numeric() > ThreatSeverity::Medium.to_numeric());
        assert!(ThreatSeverity::Medium.to_numeric() > ThreatSeverity::Low.to_numeric());

        // Test conversion
        assert_eq!(ThreatSeverity::from_numeric(4), Some(ThreatSeverity::Critical));
        assert_eq!(ThreatSeverity::from_numeric(0), None);
    }

    #[test]
    fn test_quarantine_entry() {
        let threat = ThreatInfo::new(
            "Test.Malware".to_string(),
            ThreatType::Trojan,
            ThreatSeverity::High,
            PathBuf::from("/tmp/malware.exe"),
            "c".repeat(64),
            DetectionMethod::MachineLearning,
        ).unwrap();

        let entry = QuarantineEntry::new(
            PathBuf::from("/tmp/malware.exe"),
            threat,
            1024,
            PathBuf::from("/quarantine/encrypted_file"),
        );

        assert_eq!(entry.get_file_name(), "malware.exe");
        assert_eq!(entry.get_formatted_size(), "1.00 KB");
        assert_eq!(entry.age_in_days(), 0); // Just created
        assert!(!entry.should_auto_delete(30)); // Not old enough
    }

    #[test]
    fn test_system_status() {
        let mut status = SystemStatus::new(
            "1.0.0".to_string(),
            "2023.12.01".to_string(),
        );

        // New system should need updates and scans
        assert!(status.needs_update());
        assert!(status.needs_scan());
        assert_eq!(status.get_protection_status(), "Protected");

        // Test health score
        let initial_score = status.get_health_score();
        assert!(initial_score < 100); // Should be penalized for no updates/scans

        // Disable real-time protection
        status.realtime_protection_enabled = false;
        let disabled_score = status.get_health_score();
        assert!(disabled_score < initial_score);
        assert_eq!(status.get_protection_status(), "At Risk");

        // Add some threats
        status.threats_detected_today = 5;
        let threat_score = status.get_health_score();
        assert!(threat_score < disabled_score);
    }

    #[test]
    fn test_scan_result_threat_filtering() {
        let scan_id = Uuid::new_v4();
        let mut result = ScanResult::new(scan_id);

        // Add threats of different severities
        let high_threat = ThreatInfo::new(
            "High.Threat".to_string(),
            ThreatType::Virus,
            ThreatSeverity::High,
            PathBuf::from("/tmp/high.exe"),
            "d".repeat(64),
            DetectionMethod::Signature,
        ).unwrap();

        let low_threat = ThreatInfo::new(
            "Low.Threat".to_string(),
            ThreatType::Adware,
            ThreatSeverity::Low,
            PathBuf::from("/tmp/low.exe"),
            "e".repeat(64),
            DetectionMethod::Heuristic,
        ).unwrap();

        result.add_threat(high_threat);
        result.add_threat(low_threat);

        // Test filtering
        let high_threats = result.get_threats_by_severity(ThreatSeverity::High);
        assert_eq!(high_threats.len(), 1);
        assert_eq!(high_threats[0].name, "High.Threat");

        let low_threats = result.get_threats_by_severity(ThreatSeverity::Low);
        assert_eq!(low_threats.len(), 1);
        assert_eq!(low_threats[0].name, "Low.Threat");

        let critical_threats = result.get_threats_by_severity(ThreatSeverity::Critical);
        assert_eq!(critical_threats.len(), 0);
    }

    #[test]
    fn test_file_size_formatting() {
        let entry = QuarantineEntry::new(
            PathBuf::from("/tmp/test.exe"),
            ThreatInfo::new(
                "Test".to_string(),
                ThreatType::Virus,
                ThreatSeverity::Low,
                PathBuf::from("/tmp/test.exe"),
                "f".repeat(64),
                DetectionMethod::Signature,
            ).unwrap(),
            0,
            PathBuf::from("/quarantine/test"),
        );

        // Test different file sizes
        let mut entry_bytes = entry.clone();
        entry_bytes.file_size = 512;
        assert_eq!(entry_bytes.get_formatted_size(), "512 B");

        let mut entry_kb = entry.clone();
        entry_kb.file_size = 1536; // 1.5 KB
        assert_eq!(entry_kb.get_formatted_size(), "1.50 KB");

        let mut entry_mb = entry.clone();
        entry_mb.file_size = 1572864; // 1.5 MB
        assert_eq!(entry_mb.get_formatted_size(), "1.50 MB");

        let mut entry_gb = entry;
        entry_gb.file_size = 1610612736; // 1.5 GB
        assert_eq!(entry_gb.get_formatted_size(), "1.50 GB");
    }
}