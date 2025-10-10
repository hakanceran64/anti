#[derive(Debug, Clone)]
pub enum DriverMessage {
    ScanRequest {
        file_path: std::path::PathBuf,
        process_id: u32,
    },
    ScanResponse {
        result: ScanResult,
    },
    ThreatDetected {
        threat_info: hadron_core::ThreatInfo,
    },
    ConfigUpdate {
        config: DriverConfig,
    },
    StatusRequest,
    StatusResponse {
        status: DriverStatus,
    },
}
#[derive(Debug, Clone)]
pub struct DriverConfig {
    pub enable_realtime_protection: bool,
    pub scan_on_access: bool,
    pub scan_on_write: bool,
    pub max_file_size_mb: u64,
    pub excluded_extensions: Vec<String>,
    pub excluded_paths: Vec<std::path::PathBuf>,
}
#[derive(Debug, Clone)]
pub struct DriverStatus {
    pub is_loaded: bool,
    pub version: String,
    pub last_update: chrono::DateTime<chrono::Utc>,
    pub files_scanned: u64,
    pub threats_blocked: u64,
}
#[derive(Debug, Clone)]
pub enum ScanResult {
    Clean,
    Infected(hadron_core::ThreatInfo),
    Suspicious,
    Error(String),
    Timeout,
}
pub trait DriverCommunication {
    fn send_message(&self, message: DriverMessage) -> Result<(), hadron_core::DriverError>;
    fn receive_message(&self) -> Result<DriverMessage, hadron_core::DriverError>;
    fn ping(&self) -> Result<(), hadron_core::DriverError>;
}
pub struct DriverInterface {
    minifilter_handle: Option<DriverHandle>,
    process_monitor_handle: Option<DriverHandle>,
}
impl DriverInterface {
    pub fn new() -> Self {
        Self {
            minifilter_handle: None,
            process_monitor_handle: None,
        }
    }
    pub fn connect(&mut self) -> Result<(), hadron_core::DriverError> {
        Ok(())
    }
    pub fn disconnect(&mut self) -> Result<(), hadron_core::DriverError> {
        self.minifilter_handle = None;
        self.process_monitor_handle = None;
        Ok(())
    }
    pub fn update_driver_config(&self, config: &DriverConfig) -> Result<(), hadron_core::DriverError> {
        Ok(())
    }
    pub fn get_driver_status(&self) -> Result<(DriverStatus, DriverStatus), hadron_core::DriverError> {
        let minifilter_status = DriverStatus {
            is_loaded: true,
            version: "1.0.0".to_string(),
            last_update: chrono::Utc::now(),
            files_scanned: 0,
            threats_blocked: 0,
        };
        let process_monitor_status = DriverStatus {
            is_loaded: true,
            version: "1.0.0".to_string(),
            last_update: chrono::Utc::now(),
            files_scanned: 0,
            threats_blocked: 0,
        };
        Ok((minifilter_status, process_monitor_status))
    }
}
#[derive(Debug)]
pub struct DriverHandle {
    device_name: String,
    handle: u64,
}
impl DriverHandle {
    pub fn new(device_name: String) -> Self {
        Self {
            device_name,
            handle: 0,
        }
    }
}