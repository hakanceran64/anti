use hadron_core::Result;
use hadron_core::types::AntivirusConfig;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, error, warn};
#[cfg(windows)]
use windows::{
    core::*,
    Win32::System::Services::*,
    Win32::Foundation::*,
};
#[cfg(not(windows))]
type SERVICE_STATUS_HANDLE = u32;
#[cfg(not(windows))]
const SERVICE_START_PENDING: u32 = 0x00000002;
#[cfg(not(windows))]
const SERVICE_RUNNING: u32 = 0x00000004;
#[cfg(not(windows))]
const SERVICE_STOP_PENDING: u32 = 0x00000003;
#[cfg(not(windows))]
const SERVICE_STOPPED: u32 = 0x00000001;
#[cfg(not(windows))]
const SERVICE_PAUSE_PENDING: u32 = 0x00000006;
#[cfg(not(windows))]
const SERVICE_PAUSED: u32 = 0x00000007;
#[cfg(not(windows))]
const SERVICE_CONTINUE_PENDING: u32 = 0x00000005;
pub struct WindowsServiceWrapper {
    lifecycle_manager: Arc<crate::ServiceLifecycleManager>,
    service_status_handle: Arc<RwLock<Option<SERVICE_STATUS_HANDLE>>>,
}
impl WindowsServiceWrapper {
    pub fn new(service: Arc<crate::AntivirusService>) -> Result<Self> {
        let api_server = Arc::new(crate::ApiServer::new(
            "\\\\.\\pipe\\av_service".to_string(),
            service.clone(),
        ));
        let mut lifecycle_manager = crate::ServiceLifecycleManager::new(service);
        lifecycle_manager.set_api_server(api_server);
        Ok(Self {
            lifecycle_manager: Arc::new(lifecycle_manager),
            service_status_handle: Arc::new(RwLock::new(None)),
        })
    }
    pub async fn start_service(&self) -> Result<()> {
        info!("Starting Windows antivirus service");
        self.update_service_status(SERVICE_START_PENDING).await?;
        self.lifecycle_manager.start().await?;
        self.update_service_status(SERVICE_RUNNING).await?;
        info!("Windows antivirus service started successfully");
        Ok(())
    }
    pub async fn stop_service(&self) -> Result<()> {
        info!("Stopping Windows antivirus service");
        self.update_service_status(SERVICE_STOP_PENDING).await?;
        if let Err(e) = self.lifecycle_manager.stop().await {
            error!("Failed to stop antivirus service: {}", e);
        }
        self.update_service_status(SERVICE_STOPPED).await?;
        info!("Windows antivirus service stopped");
        Ok(())
    }
    pub async fn pause_service(&self) -> Result<()> {
        info!("Pausing Windows antivirus service");
        self.update_service_status(SERVICE_PAUSE_PENDING).await?;
        self.lifecycle_manager.pause().await?;
        self.update_service_status(SERVICE_PAUSED).await?;
        info!("Windows antivirus service paused");
        Ok(())
    }
    pub async fn continue_service(&self) -> Result<()> {
        info!("Continuing Windows antivirus service");
        self.update_service_status(SERVICE_CONTINUE_PENDING).await?;
        self.lifecycle_manager.resume().await?;
        self.update_service_status(SERVICE_RUNNING).await?;
        info!("Windows antivirus service continued");
        Ok(())
    }
    pub async fn is_running(&self) -> bool {
        matches!(
            self.lifecycle_manager.get_state().await,
            crate::ServiceState::Running | crate::ServiceState::Paused
        )
    }
    pub async fn get_statistics(&self) -> Result<crate::ServiceStatistics> {
        self.lifecycle_manager.get_statistics().await
    }
    pub async fn health_check(&self) -> Result<bool> {
        self.lifecycle_manager.health_check().await
    }
    async fn update_service_status(&self, current_state: u32) -> Result<()> {
        #[cfg(windows)]
        {
            let handle_guard = self.service_status_handle.read().await;
            if let Some(handle) = *handle_guard {
                let status = SERVICE_STATUS {
                    dwServiceType: SERVICE_WIN32_OWN_PROCESS,
                    dwCurrentState: current_state,
                    dwControlsAccepted: SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_PAUSE_CONTINUE,
                    dwWin32ExitCode: 0,
                    dwServiceSpecificExitCode: 0,
                    dwCheckPoint: 0,
                    dwWaitHint: 0,
                };
                unsafe {
                    if !SetServiceStatus(handle, &status).as_bool() {
                        error!("Failed to set service status");
                        return Err(hadron_core::AntivirusError::Internal(
                            "Failed to set service status".to_string()
                        ));
                    }
                }
            }
        }
        #[cfg(not(windows))]
        {
            warn!("Service status update not supported on non-Windows platforms");
        }
        Ok(())
    }
    pub async fn set_service_status_handle(&self, handle: SERVICE_STATUS_HANDLE) {
        *self.service_status_handle.write().await = Some(handle);
    }
}
#[cfg(windows)]
pub unsafe extern "system" fn service_ctrl_handler(
    ctrl_code: u32,
    _event_type: u32,
    _event_data: *mut std::ffi::c_void,
    context: *mut std::ffi::c_void,
) -> u32 {
    if context.is_null() {
        return ERROR_CALL_NOT_IMPLEMENTED.0;
    }
    match ctrl_code {
        SERVICE_CONTROL_STOP => {
            info!("Received SERVICE_CONTROL_STOP");
            NO_ERROR.0
        }
        SERVICE_CONTROL_PAUSE => {
            info!("Received SERVICE_CONTROL_PAUSE");
            NO_ERROR.0
        }
        SERVICE_CONTROL_CONTINUE => {
            info!("Received SERVICE_CONTROL_CONTINUE");
            NO_ERROR.0
        }
        SERVICE_CONTROL_INTERROGATE => {
            NO_ERROR.0
        }
        _ => {
            warn!("Received unknown control code: {}", ctrl_code);
            ERROR_CALL_NOT_IMPLEMENTED.0
        }
    }
}
#[cfg(windows)]
pub unsafe extern "system" fn service_main(
    _argc: u32,
    _argv: *mut PWSTR,
) {
    info!("Service main function called");
    let status_handle = RegisterServiceCtrlHandlerExW(
        w!("AntivirusService"),
        Some(service_ctrl_handler),
        std::ptr::null_mut(),
    );
    if status_handle.is_invalid() {
        error!("Failed to register service control handler");
        return;
    }
    let status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: SERVICE_START_PENDING,
        dwControlsAccepted: 0,
        dwWin32ExitCode: 0,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: 0,
        dwWaitHint: 3000,
    };
    if !SetServiceStatus(status_handle, &status).as_bool() {
        error!("Failed to set initial service status");
        return;
    }
    info!("Service registered successfully");
}
#[cfg(windows)]
pub fn install_service() -> Result<()> {
    info!("Installing Windows antivirus service");
    unsafe {
        let sc_manager = OpenSCManagerW(
            PCWSTR::null(),
            PCWSTR::null(),
            SC_MANAGER_CREATE_SERVICE,
        )?;
        if sc_manager.is_invalid() {
            return Err(hadron_core::AntivirusError::Internal(
                "Failed to open service control manager".to_string()
            ));
        }
        let service_path = std::env::current_exe()
            .map_err(|e| hadron_core::AntivirusError::Internal(format!("Failed to get executable path: {}", e)))?;
        let service_path_wide: Vec<u16> = service_path
            .to_string_lossy()
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let service = CreateServiceW(
            sc_manager,
            w!("AntivirusService"),
            w!("Windows Antivirus Service"),
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_AUTO_START,
            SERVICE_ERROR_NORMAL,
            PCWSTR(service_path_wide.as_ptr()),
            PCWSTR::null(),
            std::ptr::null_mut(),
            PCWSTR::null(),
            PCWSTR::null(),
            PCWSTR::null(),
        )?;
        if service.is_invalid() {
            CloseServiceHandle(sc_manager)?;
            return Err(hadron_core::AntivirusError::Internal(
                "Failed to create service".to_string()
            ));
        }
        CloseServiceHandle(service)?;
        CloseServiceHandle(sc_manager)?;
    }
    info!("Windows antivirus service installed successfully");
    Ok(())
}
#[cfg(windows)]
pub fn uninstall_service() -> Result<()> {
    info!("Uninstalling Windows antivirus service");
    unsafe {
        let sc_manager = OpenSCManagerW(
            PCWSTR::null(),
            PCWSTR::null(),
            SC_MANAGER_CONNECT,
        )?;
        if sc_manager.is_invalid() {
            return Err(hadron_core::AntivirusError::Internal(
                "Failed to open service control manager".to_string()
            ));
        }
        let service = OpenServiceW(
            sc_manager,
            w!("AntivirusService"),
            DELETE,
        )?;
        if service.is_invalid() {
            CloseServiceHandle(sc_manager)?;
            return Err(hadron_core::AntivirusError::Internal(
                "Failed to open service".to_string()
            ));
        }
        if !DeleteService(service).as_bool() {
            CloseServiceHandle(service)?;
            CloseServiceHandle(sc_manager)?;
            return Err(hadron_core::AntivirusError::Internal(
                "Failed to delete service".to_string()
            ));
        }
        CloseServiceHandle(service)?;
        CloseServiceHandle(sc_manager)?;
    }
    info!("Windows antivirus service uninstalled successfully");
    Ok(())
}
pub async fn run_service() -> Result<()> {
    info!("Starting antivirus service");
    let config = AntivirusConfig::default();
    let antivirus_service = Arc::new(crate::AntivirusService::new(config).await?);
    let service_wrapper = WindowsServiceWrapper::new(antivirus_service)?;
    service_wrapper.start_service().await?;
    while service_wrapper.is_running().await {
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    }
    info!("Antivirus service stopped");
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn test_service_wrapper_creation() {
        let config = AntivirusConfig::default();
        let service = Arc::new(crate::AntivirusService::new(config).await.unwrap());
        let wrapper = WindowsServiceWrapper::new(service);
        assert!(wrapper.is_ok());
    }
    #[tokio::test]
    async fn test_service_lifecycle() {
        let config = AntivirusConfig::default();
        let service = Arc::new(crate::AntivirusService::new(config).await.unwrap());
        let wrapper = WindowsServiceWrapper::new(service).unwrap();
        assert!(!wrapper.is_running().await);
        wrapper.start_service().await.unwrap();
        assert!(wrapper.is_running().await);
        wrapper.pause_service().await.unwrap();
        assert!(wrapper.is_running().await);
        wrapper.continue_service().await.unwrap();
        assert!(wrapper.is_running().await);
        wrapper.stop_service().await.unwrap();
        assert!(!wrapper.is_running().await);
    }
    #[tokio::test]
    async fn test_health_check() {
        let config = AntivirusConfig::default();
        let service = Arc::new(crate::AntivirusService::new(config).await.unwrap());
        let wrapper = WindowsServiceWrapper::new(service).unwrap();
        assert!(!wrapper.health_check().await.unwrap());
        wrapper.start_service().await.unwrap();
        assert!(wrapper.health_check().await.unwrap());
    }
}