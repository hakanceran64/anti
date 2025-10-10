use hadron_core::{Result, ScanType, ScanJobId, ScanStatus, SystemStatus, ServiceAPI};
use hadron_core::{AntivirusConfig, UpdateInfo};
use hadron_core::traits::Policy;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use async_trait::async_trait;
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ApiRequest {
    StartScan {
        scan_type: ScanType,
        targets: Vec<PathBuf>,
    },
    GetScanStatus {
        job_id: ScanJobId,
    },
    CancelScan {
        job_id: ScanJobId,
    },
    UpdatePolicy {
        policy: Policy,
    },
    GetSystemStatus,
    GetQuarantineList,
    RestoreFromQuarantine {
        quarantine_id: hadron_core::QuarantineId,
    },
    DeleteFromQuarantine {
        quarantine_id: hadron_core::QuarantineId,
    },
    CheckUpdates,
    ApplyUpdates,
    GetConfiguration,
    UpdateConfiguration {
        config: AntivirusConfig,
    },
    GetScanProgress {
        job_id: ScanJobId,
    },
    GetScanResult {
        job_id: ScanJobId,
    },
    UpdateConfigurationValue {
        key: String,
        value: String,
    },
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ApiResponse {
    ScanStarted {
        job_id: ScanJobId,
    },
    ScanStatus {
        status: ScanStatus,
    },
    ScanCancelled,
    PolicyUpdated,
    SystemStatus {
        status: SystemStatus,
    },
    QuarantineList {
        entries: Vec<hadron_core::QuarantineEntry>,
    },
    QuarantineRestored,
    QuarantineDeleted,
    UpdatesAvailable {
        updates: Vec<UpdateInfo>,
    },
    UpdatesApplied,
    Configuration {
        config: AntivirusConfig,
    },
    ConfigurationUpdated,
    ScanProgress {
        progress: hadron_core::ScanProgress,
    },
    ScanResult {
        result: hadron_core::ScanResult,
    },
    Error {
        message: String,
    },
}
pub struct ApiServer {
    pipe_name: String,
    service: std::sync::Arc<crate::AntivirusService>,
    shutdown_tx: tokio::sync::broadcast::Sender<()>,
    is_running: std::sync::Arc<tokio::sync::RwLock<bool>>,
}
impl ApiServer {
    pub fn new(pipe_name: String, service: std::sync::Arc<crate::AntivirusService>) -> Self {
        let (shutdown_tx, _) = tokio::sync::broadcast::channel(1);
        Self {
            pipe_name,
            service,
            shutdown_tx,
            is_running: std::sync::Arc::new(tokio::sync::RwLock::new(false)),
        }
    }
    pub async fn start(&self) -> Result<()> {
        *self.is_running.write().await = true;
        let pipe_name = self.pipe_name.clone();
        let service = self.service.clone();
        let is_running = self.is_running.clone();
        let mut shutdown_rx = self.shutdown_tx.subscribe();
        tokio::spawn(async move {
            tracing::info!("Starting API server on pipe: {}", pipe_name);
            loop {
                tokio::select! {
                    _ = shutdown_rx.recv() => {
                        tracing::info!("API server shutdown signal received");
                        break;
                    }
                    _ = tokio::time::sleep(tokio::time::Duration::from_millis(100)) => {
                        if !*is_running.read().await {
                            break;
                        }
                        #[cfg(windows)]
                        {
                        }
                        #[cfg(not(windows))]
                        {
                        }
                    }
                }
            }
            tracing::info!("API server stopped");
        });
        tracing::info!("API server started on pipe: {}", self.pipe_name);
        Ok(())
    }
    pub async fn stop(&self) -> Result<()> {
        *self.is_running.write().await = false;
        if let Err(e) = self.shutdown_tx.send(()) {
            tracing::warn!("Failed to send shutdown signal: {}", e);
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
        tracing::info!("API server stopped");
        Ok(())
    }
    #[cfg(windows)]
    async fn handle_client_connection(&self, _pipe_handle: windows::Win32::Foundation::HANDLE) -> Result<()> {
        Ok(())
    }
    #[cfg(windows)]
    fn create_named_pipe(&self) -> Result<windows::Win32::Foundation::HANDLE> {
        use windows::Win32::Storage::FileSystem::*;
        use windows::Win32::Foundation::*;
        use windows::core::*;
        let pipe_name_wide: Vec<u16> = self.pipe_name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        unsafe {
            let handle = CreateNamedPipeW(
                PCWSTR(pipe_name_wide.as_ptr()),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES,
                4096,
                4096,
                0,
                std::ptr::null(),
            );
            if handle == INVALID_HANDLE_VALUE {
                return Err(hadron_core::AntivirusError::Internal(
                    "Failed to create named pipe".to_string()
                ));
            }
            Ok(handle)
        }
    }
    async fn handle_request(&self, request: ApiRequest) -> ApiResponse {
        match request {
            ApiRequest::StartScan { scan_type, targets } => {
                match self.service.start_scan(scan_type, targets).await {
                    Ok(job_id) => ApiResponse::ScanStarted { job_id },
                    Err(e) => ApiResponse::Error { message: e.to_string() },
                }
            }
            ApiRequest::GetScanStatus { job_id } => {
                match self.service.get_scan_status(job_id).await {
                    Ok(status) => ApiResponse::ScanStatus { status },
                    Err(e) => ApiResponse::Error { message: e.to_string() },
                }
            }
            ApiRequest::GetSystemStatus => {
                match self.service.get_system_status().await {
                    Ok(status) => ApiResponse::SystemStatus { status },
                    Err(e) => ApiResponse::Error { message: e.to_string() },
                }
            }
            ApiRequest::UpdatePolicy { policy } => {
                match self.service.update_policy(policy).await {
                    Ok(()) => ApiResponse::PolicyUpdated,
                    Err(e) => ApiResponse::Error { message: e.to_string() },
                }
            }
            _ => ApiResponse::Error {
                message: "Request not implemented".to_string(),
            },
        }
    }
}
pub struct ApiClient {
    pipe_name: String,
    #[cfg(windows)]
    pipe_handle: std::sync::Arc<tokio::sync::RwLock<Option<windows::Win32::Foundation::HANDLE>>>,
    is_connected: std::sync::Arc<tokio::sync::RwLock<bool>>,
}
impl ApiClient {
    pub fn new(pipe_name: String) -> Self {
        Self { 
            pipe_name,
            #[cfg(windows)]
            pipe_handle: std::sync::Arc::new(tokio::sync::RwLock::new(None)),
            is_connected: std::sync::Arc::new(tokio::sync::RwLock::new(false)),
        }
    }
    pub async fn connect(&self) -> Result<()> {
        if *self.is_connected.read().await {
            return Ok(());
        }
        #[cfg(windows)]
        {
            self.connect_windows().await?;
        }
        #[cfg(not(windows))]
        {
            self.connect_unix().await?;
        }
        *self.is_connected.write().await = true;
        tracing::info!("Connected to service via pipe: {}", self.pipe_name);
        Ok(())
    }
    pub async fn disconnect(&self) -> Result<()> {
        if !*self.is_connected.read().await {
            return Ok(());
        }
        #[cfg(windows)]
        {
            let mut handle_guard = self.pipe_handle.write().await;
            if let Some(handle) = handle_guard.take() {
                unsafe {
                    windows::Win32::Foundation::CloseHandle(handle);
                }
            }
        }
        *self.is_connected.write().await = false;
        tracing::info!("Disconnected from service");
        Ok(())
    }
    #[cfg(windows)]
    async fn connect_windows(&self) -> Result<()> {
        use windows::Win32::Storage::FileSystem::*;
        use windows::Win32::Foundation::*;
        use windows::core::*;
        let pipe_name_wide: Vec<u16> = self.pipe_name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        for attempt in 1..=5 {
            unsafe {
                let handle = CreateFileW(
                    PCWSTR(pipe_name_wide.as_ptr()),
                    GENERIC_READ | GENERIC_WRITE,
                    FILE_SHARE_NONE,
                    std::ptr::null(),
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL,
                    HANDLE::default(),
                );
                if handle != INVALID_HANDLE_VALUE {
                    *self.pipe_handle.write().await = Some(handle);
                    return Ok(());
                }
                if attempt < 5 {
                    tracing::warn!("Failed to connect to pipe (attempt {}), retrying...", attempt);
                    tokio::time::sleep(tokio::time::Duration::from_millis(100 * attempt)).await;
                }
            }
        }
        Err(hadron_core::AntivirusError::Internal(
            "Failed to connect to named pipe after retries".to_string()
        ))
    }
    #[cfg(not(windows))]
    async fn connect_unix(&self) -> Result<()> {
        tracing::info!("Unix socket connection simulated");
        Ok(())
    }
    pub async fn send_request(&self, request: ApiRequest) -> Result<ApiResponse> {
        if !*self.is_connected.read().await {
            self.connect().await?;
        }
        let request_data = serde_json::to_vec(&request)
            .map_err(|e| hadron_core::AntivirusError::Internal(format!("Failed to serialize request: {}", e)))?;
        #[cfg(windows)]
        {
            self.send_request_windows(&request_data).await
        }
        #[cfg(not(windows))]
        {
            self.send_request_unix(&request_data).await
        }
    }
    #[cfg(windows)]
    async fn send_request_windows(&self, request_data: &[u8]) -> Result<ApiResponse> {
        use windows::Win32::Storage::FileSystem::*;
        use windows::Win32::Foundation::*;
        let handle_guard = self.pipe_handle.read().await;
        let handle = handle_guard.as_ref()
            .ok_or_else(|| hadron_core::AntivirusError::Internal("Not connected to pipe".to_string()))?;
        unsafe {
            let mut bytes_written = 0u32;
            let write_result = WriteFile(
                *handle,
                Some(request_data),
                Some(&mut bytes_written),
                std::ptr::null_mut(),
            );
            if !write_result.as_bool() || bytes_written != request_data.len() as u32 {
                return Err(hadron_core::AntivirusError::Internal(
                    "Failed to write request to pipe".to_string()
                ));
            }
            let mut response_buffer = vec![0u8; 4096];
            let mut bytes_read = 0u32;
            let read_result = ReadFile(
                *handle,
                Some(response_buffer.as_mut_slice()),
                Some(&mut bytes_read),
                std::ptr::null_mut(),
            );
            if !read_result.as_bool() {
                return Err(hadron_core::AntivirusError::Internal(
                    "Failed to read response from pipe".to_string()
                ));
            }
            response_buffer.truncate(bytes_read as usize);
            let response: ApiResponse = serde_json::from_slice(&response_buffer)
                .map_err(|e| hadron_core::AntivirusError::Internal(format!("Failed to deserialize response: {}", e)))?;
            Ok(response)
        }
    }
    #[cfg(not(windows))]
    async fn send_request_unix(&self, _request_data: &[u8]) -> Result<ApiResponse> {
        Ok(ApiResponse::Error {
            message: "Unix socket not implemented".to_string(),
        })
    }
    pub async fn start_scan(&self, scan_type: ScanType, targets: Vec<PathBuf>) -> Result<ScanJobId> {
        let request = ApiRequest::StartScan { scan_type, targets };
        match self.send_request(request).await? {
            ApiResponse::ScanStarted { job_id } => Ok(job_id),
            ApiResponse::Error { message } => Err(hadron_core::AntivirusError::Internal(message)),
            _ => Err(hadron_core::AntivirusError::Internal("Unexpected response".to_string())),
        }
    }
    pub async fn get_scan_status(&self, job_id: ScanJobId) -> Result<ScanStatus> {
        let request = ApiRequest::GetScanStatus { job_id };
        match self.send_request(request).await? {
            ApiResponse::ScanStatus { status } => Ok(status),
            ApiResponse::Error { message } => Err(hadron_core::AntivirusError::Internal(message)),
            _ => Err(hadron_core::AntivirusError::Internal("Unexpected response".to_string())),
        }
    }
    pub async fn get_system_status(&self) -> Result<SystemStatus> {
        let request = ApiRequest::GetSystemStatus;
        match self.send_request(request).await? {
            ApiResponse::SystemStatus { status } => Ok(status),
            ApiResponse::Error { message } => Err(hadron_core::AntivirusError::Internal(message)),
            _ => Err(hadron_core::AntivirusError::Internal("Unexpected response".to_string())),
        }
    }
    pub async fn get_scan_progress(&self, job_id: ScanJobId) -> Result<hadron_core::ScanProgress> {
        let request = ApiRequest::GetScanProgress { job_id };
        match self.send_request(request).await? {
            ApiResponse::ScanProgress { progress } => Ok(progress),
            ApiResponse::Error { message } => Err(hadron_core::AntivirusError::Internal(message)),
            _ => Err(hadron_core::AntivirusError::Internal("Unexpected response".to_string())),
        }
    }
    pub async fn get_scan_result(&self, job_id: ScanJobId) -> Result<hadron_core::ScanResult> {
        let request = ApiRequest::GetScanResult { job_id };
        match self.send_request(request).await? {
            ApiResponse::ScanResult { result } => Ok(result),
            ApiResponse::Error { message } => Err(hadron_core::AntivirusError::Internal(message)),
            _ => Err(hadron_core::AntivirusError::Internal("Unexpected response".to_string())),
        }
    }
    pub async fn get_quarantine_list(&self) -> Result<Vec<hadron_core::QuarantineEntry>> {
        let request = ApiRequest::GetQuarantineList;
        match self.send_request(request).await? {
            ApiResponse::QuarantineList { entries } => Ok(entries),
            ApiResponse::Error { message } => Err(hadron_core::AntivirusError::Internal(message)),
            _ => Err(hadron_core::AntivirusError::Internal("Unexpected response".to_string())),
        }
    }
    pub async fn restore_from_quarantine(&self, quarantine_id: String) -> Result<()> {
        let quarantine_id = quarantine_id.parse()
            .map_err(|_| hadron_core::AntivirusError::Internal("Invalid quarantine ID".to_string()))?;
        let request = ApiRequest::RestoreFromQuarantine { quarantine_id };
        match self.send_request(request).await? {
            ApiResponse::QuarantineRestored => Ok(()),
            ApiResponse::Error { message } => Err(hadron_core::AntivirusError::Internal(message)),
            _ => Err(hadron_core::AntivirusError::Internal("Unexpected response".to_string())),
        }
    }
    pub async fn delete_from_quarantine(&self, quarantine_id: String) -> Result<()> {
        let quarantine_id = quarantine_id.parse()
            .map_err(|_| hadron_core::AntivirusError::Internal("Invalid quarantine ID".to_string()))?;
        let request = ApiRequest::DeleteFromQuarantine { quarantine_id };
        match self.send_request(request).await? {
            ApiResponse::QuarantineDeleted => Ok(()),
            ApiResponse::Error { message } => Err(hadron_core::AntivirusError::Internal(message)),
            _ => Err(hadron_core::AntivirusError::Internal("Unexpected response".to_string())),
        }
    }
    pub async fn check_updates(&self) -> Result<Vec<UpdateInfo>> {
        let request = ApiRequest::CheckUpdates;
        match self.send_request(request).await? {
            ApiResponse::UpdatesAvailable { updates } => Ok(updates),
            ApiResponse::Error { message } => Err(hadron_core::AntivirusError::Internal(message)),
            _ => Err(hadron_core::AntivirusError::Internal("Unexpected response".to_string())),
        }
    }
    pub async fn apply_updates(&self) -> Result<()> {
        let request = ApiRequest::ApplyUpdates;
        match self.send_request(request).await? {
            ApiResponse::UpdatesApplied => Ok(()),
            ApiResponse::Error { message } => Err(hadron_core::AntivirusError::Internal(message)),
            _ => Err(hadron_core::AntivirusError::Internal("Unexpected response".to_string())),
        }
    }
    pub async fn get_configuration(&self) -> Result<AntivirusConfig> {
        let request = ApiRequest::GetConfiguration;
        match self.send_request(request).await? {
            ApiResponse::Configuration { config } => Ok(config),
            ApiResponse::Error { message } => Err(hadron_core::AntivirusError::Internal(message)),
            _ => Err(hadron_core::AntivirusError::Internal("Unexpected response".to_string())),
        }
    }
    pub async fn update_configuration_value(&self, key: String, value: String) -> Result<()> {
        let request = ApiRequest::UpdateConfigurationValue { key, value };
        match self.send_request(request).await? {
            ApiResponse::ConfigurationUpdated => Ok(()),
            ApiResponse::Error { message } => Err(hadron_core::AntivirusError::Internal(message)),
            _ => Err(hadron_core::AntivirusError::Internal("Unexpected response".to_string())),
        }
    }
}