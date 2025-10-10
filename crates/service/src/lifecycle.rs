use hadron_core::{Result, ServiceAPI};
use hadron_core::types::AntivirusConfig;
use std::sync::Arc;
use tokio::sync::{RwLock, broadcast};
use tracing::{info, warn, error};
use async_trait::async_trait;
#[derive(Debug, Clone, PartialEq)]
pub enum ServiceState {
    Stopped,
    Starting,
    Running,
    Pausing,
    Paused,
    Resuming,
    Stopping,
    Error(String),
}
#[derive(Debug, Clone)]
pub enum ServiceEvent {
    Start,
    Stop,
    Pause,
    Resume,
    ConfigurationChanged,
    Error(String),
}
pub struct ServiceLifecycleManager {
    state: Arc<RwLock<ServiceState>>,
    event_tx: broadcast::Sender<ServiceEvent>,
    service: Arc<crate::AntivirusService>,
    api_server: Option<Arc<crate::ApiServer>>,
}
impl ServiceLifecycleManager {
    pub fn new(service: Arc<crate::AntivirusService>) -> Self {
        let (event_tx, _) = broadcast::channel(100);
        Self {
            state: Arc::new(RwLock::new(ServiceState::Stopped)),
            event_tx,
            service,
            api_server: None,
        }
    }
    pub fn set_api_server(&mut self, api_server: Arc<crate::ApiServer>) {
        self.api_server = Some(api_server);
    }
    pub async fn get_state(&self) -> ServiceState {
        self.state.read().await.clone()
    }
    pub fn subscribe_events(&self) -> broadcast::Receiver<ServiceEvent> {
        self.event_tx.subscribe()
    }
    pub async fn start(&self) -> Result<()> {
        let current_state = self.get_state().await;
        if current_state == ServiceState::Running {
            return Ok(());
        }
        info!("Starting service lifecycle");
        self.set_state(ServiceState::Starting).await;
        self.send_event(ServiceEvent::Start).await;
        match self.start_internal().await {
            Ok(()) => {
                self.set_state(ServiceState::Running).await;
                info!("Service started successfully");
                Ok(())
            }
            Err(e) => {
                let error_msg = format!("Failed to start service: {}", e);
                error!("{}", error_msg);
                self.set_state(ServiceState::Error(error_msg.clone())).await;
                self.send_event(ServiceEvent::Error(error_msg)).await;
                Err(e)
            }
        }
    }
    pub async fn stop(&self) -> Result<()> {
        let current_state = self.get_state().await;
        if current_state == ServiceState::Stopped {
            return Ok(());
        }
        info!("Stopping service lifecycle");
        self.set_state(ServiceState::Stopping).await;
        self.send_event(ServiceEvent::Stop).await;
        match self.stop_internal().await {
            Ok(()) => {
                self.set_state(ServiceState::Stopped).await;
                info!("Service stopped successfully");
                Ok(())
            }
            Err(e) => {
                let error_msg = format!("Failed to stop service: {}", e);
                error!("{}", error_msg);
                self.set_state(ServiceState::Error(error_msg.clone())).await;
                self.send_event(ServiceEvent::Error(error_msg)).await;
                Err(e)
            }
        }
    }
    pub async fn pause(&self) -> Result<()> {
        let current_state = self.get_state().await;
        if current_state != ServiceState::Running {
            return Err(hadron_core::AntivirusError::Internal(
                "Service must be running to pause".to_string()
            ));
        }
        info!("Pausing service");
        self.set_state(ServiceState::Pausing).await;
        self.send_event(ServiceEvent::Pause).await;
        match self.pause_internal().await {
            Ok(()) => {
                self.set_state(ServiceState::Paused).await;
                info!("Service paused successfully");
                Ok(())
            }
            Err(e) => {
                let error_msg = format!("Failed to pause service: {}", e);
                error!("{}", error_msg);
                self.set_state(ServiceState::Error(error_msg.clone())).await;
                self.send_event(ServiceEvent::Error(error_msg)).await;
                Err(e)
            }
        }
    }
    pub async fn resume(&self) -> Result<()> {
        let current_state = self.get_state().await;
        if current_state != ServiceState::Paused {
            return Err(hadron_core::AntivirusError::Internal(
                "Service must be paused to resume".to_string()
            ));
        }
        info!("Resuming service");
        self.set_state(ServiceState::Resuming).await;
        self.send_event(ServiceEvent::Resume).await;
        match self.resume_internal().await {
            Ok(()) => {
                self.set_state(ServiceState::Running).await;
                info!("Service resumed successfully");
                Ok(())
            }
            Err(e) => {
                let error_msg = format!("Failed to resume service: {}", e);
                error!("{}", error_msg);
                self.set_state(ServiceState::Error(error_msg.clone())).await;
                self.send_event(ServiceEvent::Error(error_msg)).await;
                Err(e)
            }
        }
    }
    pub async fn handle_configuration_change(&self, config: AntivirusConfig) -> Result<()> {
        info!("Handling configuration change");
        self.send_event(ServiceEvent::ConfigurationChanged).await;
        self.service.update_config(config).await?;
        let current_state = self.get_state().await;
        if current_state == ServiceState::Running {
            info!("Configuration updated while service is running");
        }
        Ok(())
    }
    async fn start_internal(&self) -> Result<()> {
        self.service.start().await?;
        if let Some(api_server) = &self.api_server {
            api_server.start().await?;
        }
        Ok(())
    }
    async fn stop_internal(&self) -> Result<()> {
        if let Some(api_server) = &self.api_server {
            if let Err(e) = api_server.stop().await {
                warn!("Failed to stop API server: {}", e);
            }
        }
        self.service.stop().await?;
        Ok(())
    }
    async fn pause_internal(&self) -> Result<()> {
        info!("Service paused (real-time protection disabled)");
        Ok(())
    }
    async fn resume_internal(&self) -> Result<()> {
        info!("Service resumed (real-time protection enabled)");
        Ok(())
    }
    async fn set_state(&self, new_state: ServiceState) {
        let mut state = self.state.write().await;
        *state = new_state;
    }
    async fn send_event(&self, event: ServiceEvent) {
        if let Err(e) = self.event_tx.send(event) {
            warn!("Failed to send service event: {}", e);
        }
    }
    pub async fn health_check(&self) -> Result<bool> {
        let state = self.get_state().await;
        match state {
            ServiceState::Running | ServiceState::Paused => {
                if !self.service.is_running().await {
                    return Ok(false);
                }
                if let Some(_api_server) = &self.api_server {
                }
                Ok(true)
            }
            _ => Ok(false),
        }
    }
    pub async fn get_statistics(&self) -> Result<ServiceStatistics> {
        let state = self.get_state().await;
        let system_status = self.service.get_system_status().await?;
        Ok(ServiceStatistics {
            state,
            uptime: self.calculate_uptime().await,
            system_status,
        })
    }
    async fn calculate_uptime(&self) -> std::time::Duration {
        std::time::Duration::from_secs(0)
    }
}
#[derive(Debug, Clone)]
pub struct ServiceStatistics {
    pub state: ServiceState,
    pub uptime: std::time::Duration,
    pub system_status: hadron_core::SystemStatus,
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn test_lifecycle_manager_creation() {
        let config = hadron_core::AntivirusConfig::default();
        let service = Arc::new(crate::AntivirusService::new(config).await.unwrap());
        let manager = ServiceLifecycleManager::new(service);
        assert_eq!(manager.get_state().await, ServiceState::Stopped);
    }
    #[tokio::test]
    async fn test_service_start_stop() {
        let config = hadron_core::AntivirusConfig::default();
        let service = Arc::new(crate::AntivirusService::new(config).await.unwrap());
        let manager = ServiceLifecycleManager::new(service);
        manager.start().await.unwrap();
        assert_eq!(manager.get_state().await, ServiceState::Running);
        manager.stop().await.unwrap();
        assert_eq!(manager.get_state().await, ServiceState::Stopped);
    }
    #[tokio::test]
    async fn test_service_pause_resume() {
        let config = hadron_core::AntivirusConfig::default();
        let service = Arc::new(crate::AntivirusService::new(config).await.unwrap());
        let manager = ServiceLifecycleManager::new(service);
        manager.start().await.unwrap();
        assert_eq!(manager.get_state().await, ServiceState::Running);
        manager.pause().await.unwrap();
        assert_eq!(manager.get_state().await, ServiceState::Paused);
        manager.resume().await.unwrap();
        assert_eq!(manager.get_state().await, ServiceState::Running);
    }
    #[tokio::test]
    async fn test_health_check() {
        let config = hadron_core::AntivirusConfig::default();
        let service = Arc::new(crate::AntivirusService::new(config).await.unwrap());
        let manager = ServiceLifecycleManager::new(service);
        assert!(!manager.health_check().await.unwrap());
        manager.start().await.unwrap();
        assert!(manager.health_check().await.unwrap());
    }
}