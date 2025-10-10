use async_trait::async_trait;
use std::path::Path;
use crate::{
    Result, ScanResult, ThreatInfo, QuarantineId, QuarantineEntry, 
    NetworkPacket, ProcessInfo, ThreadInfo, ImageInfo, ScanProgress,
    SystemStatus, ScanType, ScanJobId, ScanStatus, NetworkAnalysisResult,
    UrlReputation, IpReputation, NetworkMonitorStats, NetworkMonitorConfig
};

#[async_trait]
pub trait Scanner {
    async fn scan_file(&self, path: &Path) -> Result<ScanResult>;
    
    async fn scan_memory(&self, process_id: u32) -> Result<ScanResult>;
    
    async fn scan_network_packet(&self, packet: &NetworkPacket) -> Result<ScanResult>;
    
    async fn start_scan(&self, scan_type: ScanType, targets: Vec<std::path::PathBuf>) -> Result<ScanJobId>;
    
    async fn get_scan_status(&self, job_id: ScanJobId) -> Result<ScanStatus>;
    
    async fn cancel_scan(&self, job_id: ScanJobId) -> Result<()>;
}

#[async_trait]
pub trait QuarantineOperations {
    /// Move a file to quarantine
    async fn quarantine_file(&self, path: &Path, threat_info: &ThreatInfo) -> Result<QuarantineId>;
    
    /// Restore a file from quarantine
    async fn restore_file(&self, quarantine_id: QuarantineId) -> Result<()>;
    
    /// Permanently delete a quarantined file
    async fn delete_quarantined(&self, quarantine_id: QuarantineId) -> Result<()>;
    
    /// List all quarantined files
    async fn list_quarantined(&self) -> Result<Vec<QuarantineEntry>>;
    
    /// Get details of a specific quarantine entry
    async fn get_quarantine_entry(&self, quarantine_id: QuarantineId) -> Result<QuarantineEntry>;
}

/// Update management operations
#[async_trait]
pub trait UpdateOperations {
    /// Check for available updates
    async fn check_updates(&self) -> Result<Vec<UpdateInfo>>;
    
    /// Download an update package
    async fn download_update(&self, update_info: &UpdateInfo) -> Result<UpdatePackage>;
    
    /// Apply an update package
    async fn apply_update(&self, package: UpdatePackage) -> Result<()>;
    
    /// Rollback to a previous version
    async fn rollback_update(&self, version: &str) -> Result<()>;
    
    /// Get current version information
    fn get_version_info(&self) -> VersionInfo;
}

/// Machine learning classification operations
#[async_trait]
pub trait MLClassification {
    /// Extract features from file data
    async fn extract_features(&self, file_data: &[u8]) -> Result<FeatureVector>;
    
    /// Classify based on extracted features
    async fn classify(&self, features: &FeatureVector) -> Result<ClassificationResult>;
    
    /// Update the ML model
    async fn update_model(&self, model_data: &[u8]) -> Result<()>;
    
    /// Get model information
    fn get_model_info(&self) -> ModelInfo;
}

/// Sandbox execution operations
#[async_trait]
pub trait SandboxOperations {
    /// Create a new sandbox environment
    async fn create_sandbox(&self) -> Result<crate::SandboxId>;
    
    /// Execute a file in the sandbox
    async fn execute_in_sandbox(&self, sandbox_id: crate::SandboxId, file_path: &Path) -> Result<ExecutionReport>;
    
    /// Destroy a sandbox environment
    async fn destroy_sandbox(&self, sandbox_id: crate::SandboxId) -> Result<()>;
    
    /// Get sandbox status
    async fn get_sandbox_status(&self, sandbox_id: crate::SandboxId) -> Result<SandboxStatus>;
}

/// File system filtering operations (for kernel-mode driver)
pub trait FileSystemFilter {
    /// Handle file creation events
    fn pre_create(&self, callback_data: &CallbackData) -> FilterResult;
    
    /// Handle post-creation events
    fn post_create(&self, callback_data: &CallbackData) -> FilterResult;
    
    /// Handle file read events
    fn pre_read(&self, callback_data: &CallbackData) -> FilterResult;
    
    /// Handle file write events
    fn pre_write(&self, callback_data: &CallbackData) -> FilterResult;
    
    /// Handle file deletion events
    fn pre_delete(&self, callback_data: &CallbackData) -> FilterResult;
}

/// Process monitoring operations
pub trait ProcessMonitor {
    /// Handle process creation events
    fn on_process_create(&self, process_info: &ProcessInfo) -> MonitorResult;
    
    /// Handle process termination events
    fn on_process_terminate(&self, process_id: u32) -> MonitorResult;
    
    /// Handle thread creation events
    fn on_thread_create(&self, thread_info: &ThreadInfo) -> MonitorResult;
    
    /// Handle image/DLL load events
    fn on_image_load(&self, image_info: &ImageInfo) -> MonitorResult;
}

/// Configuration management operations
pub trait ConfigOperations {
    /// Get scan settings
    fn get_scan_settings(&self) -> ScanSettings;
    
    /// Get real-time protection settings
    fn get_realtime_settings(&self) -> RealtimeSettings;
    
    /// Update whitelist entries
    fn update_whitelist(&self, entries: Vec<WhitelistEntry>) -> Result<()>;
    
    /// Apply enterprise policy
    fn apply_enterprise_policy(&self, policy: EnterprisePolicy) -> Result<()>;
    
    /// Save configuration changes
    fn save_config(&self) -> Result<()>;
}

/// Network monitoring operations
#[async_trait]
pub trait NetworkMonitor: Send + Sync {
    /// Start network monitoring
    async fn start_monitoring(&self) -> crate::Result<()>;
    
    /// Stop network monitoring
    async fn stop_monitoring(&self) -> crate::Result<()>;
    
    /// Check if monitoring is active
    async fn is_monitoring(&self) -> bool;
    
    /// Analyze a network packet
    async fn analyze_packet(&self, packet: &NetworkPacket) -> crate::Result<NetworkAnalysisResult>;
    
    /// Check URL reputation
    async fn check_url_reputation(&self, url: &str) -> crate::Result<UrlReputation>;
    
    /// Check IP reputation
    async fn check_ip_reputation(&self, ip: &std::net::IpAddr) -> crate::Result<IpReputation>;
    
    /// Get monitoring statistics
    async fn get_statistics(&self) -> crate::Result<NetworkMonitorStats>;
    
    /// Update configuration
    async fn update_config(&self, config: NetworkMonitorConfig) -> crate::Result<()>;
}

/// Service API operations
#[async_trait]
pub trait ServiceAPI {
    /// Start a scan operation
    async fn start_scan(&self, scan_type: ScanType, targets: Vec<std::path::PathBuf>) -> Result<ScanJobId>;
    
    /// Get scan status
    async fn get_scan_status(&self, job_id: ScanJobId) -> Result<ScanStatus>;
    
    /// Update system policy
    async fn update_policy(&self, policy: Policy) -> Result<()>;
    
    /// Get current system status
    async fn get_system_status(&self) -> Result<SystemStatus>;
    
    /// Register for scan progress notifications
    async fn register_progress_callback(&self, callback: Box<dyn Fn(ScanProgress) + Send + Sync>) -> Result<()>;
}

// Supporting types for traits

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UpdateInfo {
    pub version: String,
    pub release_date: chrono::DateTime<chrono::Utc>,
    pub size_bytes: u64,
    pub download_url: String,
    pub signature: String,
    pub description: String,
}

#[derive(Debug)]
pub struct UpdatePackage {
    pub version: String,
    pub data: Vec<u8>,
    pub signature: String,
}

#[derive(Debug, Clone)]
pub struct VersionInfo {
    pub engine_version: String,
    pub signature_version: String,
    pub last_update: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone)]
pub struct FeatureVector {
    pub features: Vec<f32>,
    pub feature_names: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ClassificationResult {
    pub is_malicious: bool,
    pub confidence: f32,
    pub threat_type: Option<crate::ThreatType>,
    pub explanation: String,
}

#[derive(Debug, Clone)]
pub struct ModelInfo {
    pub model_version: String,
    pub model_type: String,
    pub last_updated: chrono::DateTime<chrono::Utc>,
    pub accuracy: f32,
}

#[derive(Debug, Clone)]
pub struct ExecutionReport {
    pub sandbox_id: crate::SandboxId,
    pub execution_time_ms: u64,
    pub exit_code: i32,
    pub behaviors_observed: Vec<String>,
    pub network_activity: Vec<NetworkActivity>,
    pub file_operations: Vec<FileOperation>,
    pub registry_operations: Vec<RegistryOperation>,
    pub is_malicious: bool,
}

#[derive(Debug, Clone)]
pub struct SandboxStatus {
    pub is_running: bool,
    pub start_time: chrono::DateTime<chrono::Utc>,
    pub resource_usage: ResourceUsage,
}

#[derive(Debug, Clone)]
pub struct CallbackData {
    pub file_path: std::path::PathBuf,
    pub process_id: u32,
    pub operation_type: String,
    pub flags: u32,
}

#[derive(Debug, Clone)]
pub enum FilterResult {
    Allow,
    Block,
    ScanRequired,
    Quarantine,
}

#[derive(Debug, Clone)]
pub enum MonitorResult {
    Allow,
    Block,
    Monitor,
    Alert,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScanSettings {
    pub scan_archives: bool,
    pub scan_email: bool,
    pub scan_network_drives: bool,
    pub max_file_size_mb: u64,
    pub timeout_seconds: u32,
    pub heuristic_level: u8,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RealtimeSettings {
    pub enabled: bool,
    pub scan_on_access: bool,
    pub scan_on_write: bool,
    pub scan_downloads: bool,
    pub scan_removable_media: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WhitelistEntry {
    pub path: std::path::PathBuf,
    pub hash: Option<String>,
    pub expiry: Option<chrono::DateTime<chrono::Utc>>,
    pub reason: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EnterprisePolicy {
    pub policy_version: String,
    pub scan_settings: ScanSettings,
    pub realtime_settings: RealtimeSettings,
    pub update_settings: UpdateSettings,
    pub restrictions: PolicyRestrictions,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Policy {
    pub local_settings: LocalSettings,
    pub enterprise_policy: Option<EnterprisePolicy>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LocalSettings {
    pub scan_settings: ScanSettings,
    pub realtime_settings: RealtimeSettings,
    pub ui_settings: UISettings,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UpdateSettings {
    pub auto_update: bool,
    pub update_frequency_hours: u32,
    pub update_server_url: String,
    pub use_delta_updates: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PolicyRestrictions {
    pub allow_user_whitelist: bool,
    pub allow_disable_realtime: bool,
    pub allow_quarantine_restore: bool,
    pub require_admin_for_settings: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UISettings {
    pub language: String,
    pub show_notifications: bool,
    pub notification_level: NotificationLevel,
    pub theme: UITheme,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum NotificationLevel {
    All,
    ThreatsOnly,
    Critical,
    None,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum UITheme {
    Light,
    Dark,
    System,
}

#[derive(Debug, Clone)]
pub struct NetworkActivity {
    pub destination: String,
    pub port: u16,
    pub protocol: String,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

#[derive(Debug, Clone)]
pub struct FileOperation {
    pub operation: String,
    pub file_path: std::path::PathBuf,
    pub success: bool,
}

#[derive(Debug, Clone)]
pub struct RegistryOperation {
    pub operation: String,
    pub key_path: String,
    pub value_name: Option<String>,
    pub success: bool,
}

#[derive(Debug, Clone, Default)]
pub struct ResourceUsage {
    pub cpu_percent: f32,
    pub memory_mb: u64,
    pub disk_io_mb: u64,
    pub network_io_mb: u64,
}