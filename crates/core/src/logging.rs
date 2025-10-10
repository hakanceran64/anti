use tracing::{info, warn, error, debug};
use tracing_subscriber::{
    fmt::{self, format::FmtSpan},
    layer::SubscriberExt,
    util::SubscriberInitExt,
    EnvFilter, Layer,
};
use tracing_appender::{non_blocking, rolling};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};
use crate::config::LoggingConfig;
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
#[cfg(windows)]
use windows::Win32::System::EventLog::{
    RegisterEventSourceW, ReportEventW, DeregisterEventSource,
    EVENTLOG_ERROR_TYPE, EVENTLOG_WARNING_TYPE, EVENTLOG_INFORMATION_TYPE,
};
#[cfg(windows)]
use windows::core::{PCWSTR, PWSTR};
#[cfg(windows)]
use std::ffi::OsStr;
#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;
pub fn init_logging(config: &LoggingConfig) -> Result<(), Box<dyn std::error::Error>> {
    let mut layers = Vec::new();
    let env_filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(&config.log_level))?;
    if config.enable_console_logging {
        let console_layer = fmt::layer()
            .with_target(true)
            .with_thread_ids(true)
            .with_span_events(FmtSpan::CLOSE)
            .boxed();
        layers.push(console_layer);
    }
    if let Some(parent) = config.log_file_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let file_appender = rolling::daily(
        config.log_file_path.parent().unwrap_or(Path::new(".")),
        config.log_file_path.file_name().unwrap_or(std::ffi::OsStr::new("antivirus.log"))
    );
    let (non_blocking_appender, _guard) = non_blocking(file_appender);
    let file_layer = if config.enable_json_logging {
        fmt::layer()
            .json()
            .with_writer(non_blocking_appender)
            .with_target(true)
            .with_thread_ids(true)
            .with_span_events(FmtSpan::CLOSE)
            .boxed()
    } else {
        fmt::layer()
            .with_writer(non_blocking_appender)
            .with_target(true)
            .with_thread_ids(true)
            .with_span_events(FmtSpan::CLOSE)
            .boxed()
    };
    layers.push(file_layer);
    #[cfg(windows)]
    if config.enable_windows_event_log {
        let event_log_layer = WindowsEventLogLayer::new("WindowsAntivirus")?;
        layers.push(event_log_layer.boxed());
    }
    match tracing_subscriber::registry()
        .with(env_filter)
        .with(layers)
        .try_init()
    {
        Ok(()) => {
            info!("Logging system initialized");
            Ok(())
        }
        Err(e) => {
            let error_msg = e.to_string();
            if error_msg.contains("global default trace dispatcher has already been set") {
                Ok(())
            } else {
                Err(Box::new(e))
            }
        }
    }
}
pub fn log_security_event(
    event_type: &str,
    severity: SecurityEventSeverity,
    message: &str,
    additional_data: Option<&serde_json::Value>,
) {
    let event_severity = match severity {
        SecurityEventSeverity::Critical => EventSeverity::Critical,
        SecurityEventSeverity::High => EventSeverity::High,
        SecurityEventSeverity::Medium => EventSeverity::Medium,
        SecurityEventSeverity::Low => EventSeverity::Low,
    };
    let mut structured_event = StructuredEvent::new(
        event_type,
        event_severity,
        "security_monitor",
        message,
    );
    if let Some(data) = additional_data {
        structured_event = structured_event.with_details(data.clone());
    }
    match severity {
        SecurityEventSeverity::Critical => {
            error!(
                event_type = %event_type,
                severity = ?severity,
                timestamp = %structured_event.timestamp,
                additional_data = ?additional_data,
                "SECURITY EVENT: {}",
                message
            );
        }
        SecurityEventSeverity::High => {
            warn!(
                event_type = %event_type,
                severity = ?severity,
                timestamp = %structured_event.timestamp,
                additional_data = ?additional_data,
                "SECURITY EVENT: {}",
                message
            );
        }
        SecurityEventSeverity::Medium | SecurityEventSeverity::Low => {
            info!(
                event_type = %event_type,
                severity = ?severity,
                timestamp = %structured_event.timestamp,
                additional_data = ?additional_data,
                "SECURITY EVENT: {}",
                message
            );
        }
    }
}
pub fn log_structured_security_event(
    event_logger: &EventLogger,
    event_type: &str,
    severity: EventSeverity,
    message: &str,
    user: Option<&str>,
    details: Option<serde_json::Value>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut event = StructuredEvent::new(event_type, severity, "security_monitor", message);
    if let Some(user) = user {
        event = event.with_user(user);
    }
    if let Some(details) = details {
        event = event.with_details(details);
    }
    event_logger.log_structured_event(event)
}
pub fn log_structured_scan_event(
    event_logger: &EventLogger,
    scan_id: &crate::ScanId,
    event_type: &str,
    message: &str,
    details: Option<serde_json::Value>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut event = StructuredEvent::new(event_type, EventSeverity::Medium, "scan_engine", message);
    let scan_details = serde_json::json!({
        "scan_id": scan_id.to_string(),
        "additional_details": details
    });
    event = event.with_details(scan_details);
    event_logger.log_structured_event(event)
}
pub fn log_structured_threat_event(
    event_logger: &EventLogger,
    threat_info: &crate::ThreatInfo,
) -> Result<(), Box<dyn std::error::Error>> {
    let severity = match threat_info.severity {
        crate::ThreatSeverity::Critical => EventSeverity::Critical,
        crate::ThreatSeverity::High => EventSeverity::High,
        crate::ThreatSeverity::Medium => EventSeverity::Medium,
        crate::ThreatSeverity::Low => EventSeverity::Low,
    };
    let details = serde_json::json!({
        "threat_id": threat_info.id.to_string(),
        "threat_name": threat_info.name,
        "threat_type": threat_info.threat_type,
        "file_path": threat_info.file_path.display().to_string(),
        "file_hash": threat_info.file_hash,
        "detection_method": threat_info.detection_method,
        "additional_info": threat_info.additional_info
    });
    let message = format!("Threat detected: {} in {}", threat_info.name, threat_info.file_path.display());
    let event = StructuredEvent::new("threat_detection", severity, "threat_detector", &message)
        .with_details(details);
    event_logger.log_structured_event(event)
}
pub fn log_structured_quarantine_event(
    event_logger: &EventLogger,
    operation: QuarantineOperation,
    quarantine_id: &crate::QuarantineId,
    file_path: &Path,
    result: &Result<(), crate::AntivirusError>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (severity, message) = match result {
        Ok(()) => (
            EventSeverity::Medium,
            format!("Quarantine operation {:?} successful for {}", operation, file_path.display())
        ),
        Err(e) => (
            EventSeverity::High,
            format!("Quarantine operation {:?} failed for {}: {}", operation, file_path.display(), e)
        ),
    };
    let details = serde_json::json!({
        "operation": operation,
        "quarantine_id": quarantine_id.to_string(),
        "file_path": file_path.display().to_string(),
        "success": result.is_ok(),
        "error": result.as_ref().err().map(|e| e.to_string())
    });
    let event = StructuredEvent::new("quarantine_operation", severity, "quarantine_manager", &message)
        .with_details(details);
    event_logger.log_structured_event(event)
}
pub fn log_scan_event(scan_id: &crate::ScanId, event: ScanEvent) {
    info!(
        scan_id = %scan_id,
        event_type = ?event.event_type,
        timestamp = %event.timestamp,
        details = ?event.details,
        "SCAN EVENT: {}",
        event.message
    );
}
pub fn log_threat_detection(threat_info: &crate::ThreatInfo) {
    warn!(
        threat_id = %threat_info.id,
        threat_name = %threat_info.name,
        threat_type = ?threat_info.threat_type,
        severity = ?threat_info.severity,
        file_path = %threat_info.file_path.display(),
        detection_method = ?threat_info.detection_method,
        timestamp = %threat_info.timestamp,
        "THREAT DETECTED: {} in {}",
        threat_info.name,
        threat_info.file_path.display()
    );
}
pub fn log_quarantine_operation(
    operation: QuarantineOperation,
    quarantine_id: &crate::QuarantineId,
    file_path: &Path,
    result: &Result<(), crate::AntivirusError>,
) {
    match result {
        Ok(()) => {
            info!(
                operation = ?operation,
                quarantine_id = %quarantine_id,
                file_path = %file_path.display(),
                "QUARANTINE OPERATION: {:?} successful for {}",
                operation,
                file_path.display()
            );
        }
        Err(e) => {
            error!(
                operation = ?operation,
                quarantine_id = %quarantine_id,
                file_path = %file_path.display(),
                error = %e,
                "QUARANTINE OPERATION: {:?} failed for {}: {}",
                operation,
                file_path.display(),
                e
            );
        }
    }
}
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub enum SecurityEventSeverity {
    Low,
    Medium,
    High,
    Critical,
}
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SecurityEvent {
    pub event_type: String,
    pub severity: SecurityEventSeverity,
    pub message: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub additional_data: Option<serde_json::Value>,
}
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum ScanEventType {
    ScanStarted,
    ScanCompleted,
    ScanCancelled,
    ScanFailed,
    FileScanned,
    ThreatDetected,
    FileQuarantined,
    FileSkipped,
}
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScanEvent {
    pub event_type: ScanEventType,
    pub message: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub details: Option<serde_json::Value>,
}
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum QuarantineOperation {
    Quarantine,
    Restore,
    Delete,
    List,
}
pub struct EventLogger {
    config: LoggingConfig,
    audit_logger: AuditLogger,
    log_rotator: LogRotator,
    event_counters: Arc<Mutex<HashMap<String, u64>>>,
    #[cfg(windows)]
    windows_event_handle: Option<windows::Win32::Foundation::HANDLE>,
}
impl EventLogger {
    pub fn new(config: LoggingConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let audit_logger = AuditLogger::new(true);
        let log_rotator = LogRotator::new(&config)?;
        let event_counters = Arc::new(Mutex::new(HashMap::new()));
        #[cfg(windows)]
        let windows_event_handle = if config.enable_windows_event_log {
            Some(Self::register_windows_event_source("WindowsAntivirus")?)
        } else {
            None
        };
        Ok(Self {
            config,
            audit_logger,
            log_rotator,
            event_counters,
            #[cfg(windows)]
            windows_event_handle,
        })
    }
    pub fn initialize(&self) -> Result<(), Box<dyn std::error::Error>> {
        match init_logging(&self.config) {
            Ok(()) => {
                info!("EventLogger system initialized with comprehensive logging support");
            }
            Err(e) => {
                let error_msg = e.to_string();
                if error_msg.contains("global default trace dispatcher has already been set") {
                    info!("EventLogger using existing logging configuration");
                } else {
                    return Err(e);
                }
            }
        }
        Ok(())
    }
    pub fn log_structured_event(&self, event: StructuredEvent) -> Result<(), Box<dyn std::error::Error>> {
        {
            let mut counters = self.event_counters.lock().unwrap();
            *counters.entry(event.event_type.clone()).or_insert(0) += 1;
        }
        let json_event = serde_json::to_string(&event)?;
        match event.severity {
            EventSeverity::Critical => {
                error!(
                    event_type = %event.event_type,
                    severity = ?event.severity,
                    timestamp = %event.timestamp,
                    source = %event.source,
                    user = %event.user.as_deref().unwrap_or("system"),
                    structured_data = %json_event,
                    "STRUCTURED EVENT: {}",
                    event.message
                );
                #[cfg(windows)]
                if let Some(handle) = self.windows_event_handle {
                    self.write_to_windows_event_log(handle, &event, EVENTLOG_ERROR_TYPE)?;
                }
            }
            EventSeverity::High => {
                warn!(
                    event_type = %event.event_type,
                    severity = ?event.severity,
                    timestamp = %event.timestamp,
                    source = %event.source,
                    user = %event.user.as_deref().unwrap_or("system"),
                    structured_data = %json_event,
                    "STRUCTURED EVENT: {}",
                    event.message
                );
                #[cfg(windows)]
                if let Some(handle) = self.windows_event_handle {
                    self.write_to_windows_event_log(handle, &event, EVENTLOG_WARNING_TYPE)?;
                }
            }
            EventSeverity::Medium | EventSeverity::Low => {
                info!(
                    event_type = %event.event_type,
                    severity = ?event.severity,
                    timestamp = %event.timestamp,
                    source = %event.source,
                    user = %event.user.as_deref().unwrap_or("system"),
                    structured_data = %json_event,
                    "STRUCTURED EVENT: {}",
                    event.message
                );
                #[cfg(windows)]
                if let Some(handle) = self.windows_event_handle {
                    self.write_to_windows_event_log(handle, &event, EVENTLOG_INFORMATION_TYPE)?;
                }
            }
            EventSeverity::Debug => {
                debug!(
                    event_type = %event.event_type,
                    severity = ?event.severity,
                    timestamp = %event.timestamp,
                    source = %event.source,
                    user = %event.user.as_deref().unwrap_or("system"),
                    structured_data = %json_event,
                    "STRUCTURED EVENT: {}",
                    event.message
                );
            }
        }
        self.log_rotator.check_and_rotate()?;
        Ok(())
    }
    pub fn log_audit_event(&self, event: AuditEvent) -> Result<(), Box<dyn std::error::Error>> {
        self.audit_logger.log_audit_event(event);
        Ok(())
    }
    pub fn get_event_statistics(&self) -> HashMap<String, u64> {
        self.event_counters.lock().unwrap().clone()
    }
    pub fn archive_logs(&self) -> Result<(), Box<dyn std::error::Error>> {
        self.log_rotator.archive_old_logs()?;
        info!("Log archiving completed");
        Ok(())
    }
    pub fn cleanup_old_logs(&self, days_to_keep: u32) -> Result<(), Box<dyn std::error::Error>> {
        self.log_rotator.cleanup_old_logs(days_to_keep)?;
        info!("Old log cleanup completed, kept logs from last {} days", days_to_keep);
        Ok(())
    }
    #[cfg(windows)]
    fn register_windows_event_source(source_name: &str) -> Result<windows::Win32::Foundation::HANDLE, Box<dyn std::error::Error>> {
        let source_name_wide: Vec<u16> = OsStr::new(source_name)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        unsafe {
            let handle = RegisterEventSourceW(None, PCWSTR(source_name_wide.as_ptr()));
            if handle.is_invalid() {
                return Err("Failed to register Windows Event Log source".into());
            }
            Ok(handle)
        }
    }
    #[cfg(windows)]
    fn write_to_windows_event_log(
        &self,
        handle: windows::Win32::Foundation::HANDLE,
        event: &StructuredEvent,
        event_type: u16,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let message_wide: Vec<u16> = OsStr::new(&event.message)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let strings = [PCWSTR(message_wide.as_ptr())];
        unsafe {
            let result = ReportEventW(
                handle,
                event_type,
                0,
                1000,
                None,
                &strings,
                None,
            );
            if !result.as_bool() {
                return Err("Failed to write to Windows Event Log".into());
            }
        }
        Ok(())
    }
}
impl Drop for EventLogger {
    fn drop(&mut self) {
        #[cfg(windows)]
        if let Some(handle) = self.windows_event_handle {
            unsafe {
                let _ = DeregisterEventSource(handle);
            }
        }
    }
}
pub struct LogRotator {
    log_file_path: PathBuf,
    max_file_size_mb: u64,
    max_files: u32,
    archive_path: PathBuf,
}
impl LogRotator {
    pub fn new(config: &LoggingConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let archive_path = config.log_file_path
            .parent()
            .unwrap_or(Path::new("."))
            .join("archive");
        fs::create_dir_all(&archive_path)?;
        Ok(Self {
            log_file_path: config.log_file_path.clone(),
            max_file_size_mb: config.max_log_file_size_mb,
            max_files: config.max_log_files,
            archive_path,
        })
    }
    pub fn check_and_rotate(&self) -> Result<(), Box<dyn std::error::Error>> {
        if !self.log_file_path.exists() {
            return Ok(());
        }
        let metadata = fs::metadata(&self.log_file_path)?;
        let file_size_mb = metadata.len() / (1024 * 1024);
        if file_size_mb >= self.max_file_size_mb {
            self.rotate_log()?;
        }
        Ok(())
    }
    fn rotate_log(&self) -> Result<(), Box<dyn std::error::Error>> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs();
        let file_name = self.log_file_path
            .file_stem()
            .unwrap_or(std::ffi::OsStr::new("antivirus"))
            .to_string_lossy();
        let extension = self.log_file_path
            .extension()
            .unwrap_or(std::ffi::OsStr::new("log"))
            .to_string_lossy();
        let rotated_name = format!("{}_{}.{}", file_name, timestamp, extension);
        let rotated_path = self.archive_path.join(rotated_name);
        fs::rename(&self.log_file_path, &rotated_path)?;
        info!("Log file rotated to: {}", rotated_path.display());
        self.cleanup_excess_files()?;
        Ok(())
    }
    pub fn archive_old_logs(&self) -> Result<(), Box<dyn std::error::Error>> {
        let entries = fs::read_dir(&self.archive_path)?;
        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() && path.extension().map_or(false, |ext| ext == "log") {
                let archived_name = format!("{}.archived", path.file_name().unwrap().to_string_lossy());
                let archived_path = path.with_file_name(archived_name);
                fs::rename(&path, &archived_path)?;
            }
        }
        Ok(())
    }
    pub fn cleanup_old_logs(&self, days_to_keep: u32) -> Result<(), Box<dyn std::error::Error>> {
        let cutoff_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs() - (days_to_keep as u64 * 24 * 60 * 60);
        let entries = fs::read_dir(&self.archive_path)?;
        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() {
                let metadata = fs::metadata(&path)?;
                if let Ok(created) = metadata.created() {
                    let created_timestamp = created.duration_since(UNIX_EPOCH)?.as_secs();
                    if created_timestamp < cutoff_time {
                        fs::remove_file(&path)?;
                        debug!("Removed old log file: {}", path.display());
                    }
                }
            }
        }
        Ok(())
    }
    fn cleanup_excess_files(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut entries: Vec<_> = fs::read_dir(&self.archive_path)?
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.path().is_file())
            .collect();
        entries.sort_by(|a, b| {
            let a_time = a.metadata().and_then(|m| m.created()).unwrap_or(SystemTime::UNIX_EPOCH);
            let b_time = b.metadata().and_then(|m| m.created()).unwrap_or(SystemTime::UNIX_EPOCH);
            b_time.cmp(&a_time)
        });
        if entries.len() > self.max_files as usize {
            for entry in entries.iter().skip(self.max_files as usize) {
                fs::remove_file(entry.path())?;
                debug!("Removed excess log file: {}", entry.path().display());
            }
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructuredEvent {
    pub event_id: String,
    pub event_type: String,
    pub severity: EventSeverity,
    pub timestamp: DateTime<Utc>,
    pub source: String,
    pub user: Option<String>,
    pub message: String,
    pub details: Option<serde_json::Value>,
    pub correlation_id: Option<String>,
    pub session_id: Option<String>,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum EventSeverity {
    Debug,
    Low,
    Medium,
    High,
    Critical,
}
impl StructuredEvent {
    pub fn new(
        event_type: &str,
        severity: EventSeverity,
        source: &str,
        message: &str,
    ) -> Self {
        Self {
            event_id: uuid::Uuid::new_v4().to_string(),
            event_type: event_type.to_string(),
            severity,
            timestamp: Utc::now(),
            source: source.to_string(),
            user: None,
            message: message.to_string(),
            details: None,
            correlation_id: None,
            session_id: None,
        }
    }
    pub fn with_user(mut self, user: &str) -> Self {
        self.user = Some(user.to_string());
        self
    }
    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }
    pub fn with_correlation_id(mut self, correlation_id: &str) -> Self {
        self.correlation_id = Some(correlation_id.to_string());
        self
    }
    pub fn with_session_id(mut self, session_id: &str) -> Self {
        self.session_id = Some(session_id.to_string());
        self
    }
}
#[cfg(windows)]
pub struct WindowsEventLogLayer {
    source_name: String,
    event_handle: Option<windows::Win32::Foundation::HANDLE>,
}
#[cfg(windows)]
impl WindowsEventLogLayer {
    pub fn new(source_name: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let source_name_wide: Vec<u16> = OsStr::new(source_name)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let event_handle = unsafe {
            let handle = RegisterEventSourceW(None, PCWSTR(source_name_wide.as_ptr()));
            if handle.is_invalid() {
                None
            } else {
                Some(handle)
            }
        };
        Ok(Self {
            source_name: source_name.to_string(),
            event_handle,
        })
    }
}
#[cfg(windows)]
impl<S> Layer<S> for WindowsEventLogLayer
where
    S: tracing::Subscriber,
{
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        if let Some(handle) = self.event_handle {
            let level = event.metadata().level();
            let target = event.metadata().target();
            let message = format!("[{}] {}: Event from tracing", level, target);
            let message_wide: Vec<u16> = OsStr::new(&message)
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();
            let strings = [PCWSTR(message_wide.as_ptr())];
            let event_type = match *level {
                tracing::Level::ERROR => EVENTLOG_ERROR_TYPE,
                tracing::Level::WARN => EVENTLOG_WARNING_TYPE,
                _ => EVENTLOG_INFORMATION_TYPE,
            };
            unsafe {
                let _ = ReportEventW(
                    handle,
                    event_type,
                    0,
                    1001,
                    None,
                    &strings,
                    None,
                );
            }
        }
    }
}
#[cfg(windows)]
impl Drop for WindowsEventLogLayer {
    fn drop(&mut self) {
        if let Some(handle) = self.event_handle {
            unsafe {
                let _ = DeregisterEventSource(handle);
            }
        }
    }
}
pub struct AuditLogger {
    enabled: bool,
}
impl AuditLogger {
    pub fn new(enabled: bool) -> Self {
        Self { enabled }
    }
    pub fn log_audit_event(&self, event: AuditEvent) {
        if !self.enabled {
            return;
        }
        info!(
            event_type = ?event.event_type,
            user = %event.user,
            timestamp = %event.timestamp,
            resource = %event.resource,
            action = %event.action,
            result = ?event.result,
            details = ?event.details,
            "AUDIT EVENT: {} performed {} on {} with result {:?}",
            event.user,
            event.action,
            event.resource,
            event.result
        );
    }
}
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AuditEvent {
    pub event_type: AuditEventType,
    pub user: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub resource: String,
    pub action: String,
    pub result: AuditResult,
    pub details: Option<serde_json::Value>,
}
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum AuditEventType {
    Authentication,
    Authorization,
    Configuration,
    ScanOperation,
    QuarantineOperation,
    UpdateOperation,
    PolicyChange,
}
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum AuditResult {
    Success,
    Failure,
    Partial,
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;
    #[test]
    fn test_structured_event_creation() {
        let event = StructuredEvent::new(
            "test_event",
            EventSeverity::Medium,
            "test_source",
            "Test message"
        );
        assert_eq!(event.event_type, "test_event");
        assert!(matches!(event.severity, EventSeverity::Medium));
        assert_eq!(event.source, "test_source");
        assert_eq!(event.message, "Test message");
        assert!(event.user.is_none());
        assert!(event.details.is_none());
    }
    #[test]
    fn test_structured_event_with_details() {
        let details = serde_json::json!({
            "key1": "value1",
            "key2": 42
        });
        let event = StructuredEvent::new(
            "test_event",
            EventSeverity::High,
            "test_source",
            "Test message"
        )
        .with_user("test_user")
        .with_details(details.clone())
        .with_correlation_id("corr-123")
        .with_session_id("sess-456");
        assert_eq!(event.user, Some("test_user".to_string()));
        assert_eq!(event.details, Some(details));
        assert_eq!(event.correlation_id, Some("corr-123".to_string()));
        assert_eq!(event.session_id, Some("sess-456".to_string()));
    }
    #[test]
    fn test_log_rotator_creation() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("test.log");
        let config = LoggingConfig {
            log_level: "info".to_string(),
            log_file_path: log_path.clone(),
            max_log_file_size_mb: 10,
            max_log_files: 5,
            enable_console_logging: false,
            enable_windows_event_log: false,
            enable_json_logging: true,
        };
        let rotator = LogRotator::new(&config);
        assert!(rotator.is_ok());
        let rotator = rotator.unwrap();
        assert_eq!(rotator.log_file_path, log_path);
        assert_eq!(rotator.max_file_size_mb, 10);
        assert_eq!(rotator.max_files, 5);
    }
    #[test]
    fn test_log_rotation_check() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("test.log");
        let config = LoggingConfig {
            log_level: "info".to_string(),
            log_file_path: log_path.clone(),
            max_log_file_size_mb: 1,
            max_log_files: 3,
            enable_console_logging: false,
            enable_windows_event_log: false,
            enable_json_logging: true,
        };
        let rotator = LogRotator::new(&config).unwrap();
        fs::write(&log_path, "small log content").unwrap();
        assert!(rotator.check_and_rotate().is_ok());
        assert!(log_path.exists());
        assert!(log_path.exists());
    }
    #[test]
    fn test_event_logger_creation() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("test.log");
        let config = LoggingConfig {
            log_level: "info".to_string(),
            log_file_path: log_path,
            max_log_file_size_mb: 10,
            max_log_files: 5,
            enable_console_logging: false,
            enable_windows_event_log: false,
            enable_json_logging: true,
        };
        let event_logger = EventLogger::new(config);
        assert!(event_logger.is_ok());
        let event_logger = event_logger.unwrap();
        let stats = event_logger.get_event_statistics();
        assert!(stats.is_empty());
    }
    #[test]
    fn test_structured_event_logging() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("test.log");
        let config = LoggingConfig {
            log_level: "info".to_string(),
            log_file_path: log_path,
            max_log_file_size_mb: 10,
            max_log_files: 5,
            enable_console_logging: false,
            enable_windows_event_log: false,
            enable_json_logging: true,
        };
        let event_logger = EventLogger::new(config).unwrap();
        let event = StructuredEvent::new(
            "test_event",
            EventSeverity::Medium,
            "test_source",
            "Test structured event"
        );
        let result = event_logger.log_structured_event(event);
        assert!(result.is_ok());
        let stats = event_logger.get_event_statistics();
        assert_eq!(stats.get("test_event"), Some(&1));
    }
    #[test]
    fn test_audit_event_creation() {
        let audit_event = AuditEvent {
            event_type: AuditEventType::ScanOperation,
            user: "test_user".to_string(),
            timestamp: Utc::now(),
            resource: "C:\\test\\file.exe".to_string(),
            action: "scan".to_string(),
            result: AuditResult::Success,
            details: Some(serde_json::json!({"scan_duration": 1500})),
        };
        assert_eq!(audit_event.user, "test_user");
        assert_eq!(audit_event.resource, "C:\\test\\file.exe");
        assert_eq!(audit_event.action, "scan");
        assert!(matches!(audit_event.result, AuditResult::Success));
    }
    #[test]
    fn test_event_severity_conversion() {
        let security_severity = SecurityEventSeverity::Critical;
        let event_severity = match security_severity {
            SecurityEventSeverity::Critical => EventSeverity::Critical,
            SecurityEventSeverity::High => EventSeverity::High,
            SecurityEventSeverity::Medium => EventSeverity::Medium,
            SecurityEventSeverity::Low => EventSeverity::Low,
        };
        assert!(matches!(event_severity, EventSeverity::Critical));
    }
    #[test]
    fn test_log_cleanup() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("test.log");
        let config = LoggingConfig {
            log_level: "info".to_string(),
            log_file_path: log_path,
            max_log_file_size_mb: 10,
            max_log_files: 2,
            enable_console_logging: false,
            enable_windows_event_log: false,
            enable_json_logging: true,
        };
        let rotator = LogRotator::new(&config).unwrap();
        let result = rotator.cleanup_old_logs(0);
        assert!(result.is_ok());
    }
    #[test]
    fn test_json_serialization() {
        let event = StructuredEvent::new(
            "test_event",
            EventSeverity::High,
            "test_source",
            "Test message"
        );
        let json_result = serde_json::to_string(&event);
        assert!(json_result.is_ok());
        let json_str = json_result.unwrap();
        let deserialized: Result<StructuredEvent, _> = serde_json::from_str(&json_str);
        assert!(deserialized.is_ok());
        let deserialized_event = deserialized.unwrap();
        assert_eq!(deserialized_event.event_type, event.event_type);
        assert_eq!(deserialized_event.message, event.message);
    }
}