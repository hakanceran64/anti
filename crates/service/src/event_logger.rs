use hadron_core::{
    EventLogger as CoreEventLogger, StructuredEvent, EventSeverity, AuditEvent, AuditEventType, 
    AuditResult, AntivirusError, ThreatInfo, ScanId, QuarantineId, QuarantineOperation,
    log_structured_threat_event, log_structured_quarantine_event
};
use hadron_core::config::LoggingConfig;
use std::sync::Arc;
use std::path::Path;
use tokio::sync::RwLock;
use serde_json;
use chrono::Utc;

/// Service-level EventLogger that wraps the core EventLogger with additional functionality
pub struct ServiceEventLogger {
    core_logger: Arc<RwLock<CoreEventLogger>>,
    service_name: String,
}

impl ServiceEventLogger {
    /// Create a new ServiceEventLogger
    pub fn new(config: LoggingConfig, service_name: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let core_logger = CoreEventLogger::new(config)?;
        core_logger.initialize()?;
        
        Ok(Self {
            core_logger: Arc::new(RwLock::new(core_logger)),
            service_name: service_name.to_string(),
        })
    }

    /// Log service startup event
    pub async fn log_service_startup(&self) -> Result<(), Box<dyn std::error::Error>> {
        let logger = self.core_logger.read().await;
        let event = StructuredEvent::new(
            "service_startup",
            EventSeverity::Medium,
            &self.service_name,
            &format!("{} service started successfully", self.service_name),
        );
        logger.log_structured_event(event)
    }

    /// Log service shutdown event
    pub async fn log_service_shutdown(&self) -> Result<(), Box<dyn std::error::Error>> {
        let logger = self.core_logger.read().await;
        let event = StructuredEvent::new(
            "service_shutdown",
            EventSeverity::Medium,
            &self.service_name,
            &format!("{} service shutting down", self.service_name),
        );
        logger.log_structured_event(event)
    }

    /// Log configuration change event
    pub async fn log_configuration_change(
        &self,
        user: &str,
        setting_name: &str,
        old_value: &str,
        new_value: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let logger = self.core_logger.read().await;
        
        let details = serde_json::json!({
            "setting_name": setting_name,
            "old_value": old_value,
            "new_value": new_value,
            "change_timestamp": Utc::now()
        });

        let event = StructuredEvent::new(
            "configuration_change",
            EventSeverity::Medium,
            &self.service_name,
            &format!("Configuration setting '{}' changed from '{}' to '{}'", setting_name, old_value, new_value),
        )
        .with_user(user)
        .with_details(details);

        logger.log_structured_event(event)?;

        // Also log as audit event
        let audit_event = AuditEvent {
            event_type: AuditEventType::Configuration,
            user: user.to_string(),
            timestamp: Utc::now(),
            resource: setting_name.to_string(),
            action: "modify".to_string(),
            result: AuditResult::Success,
            details: Some(serde_json::json!({
                "old_value": old_value,
                "new_value": new_value
            })),
        };

        logger.log_audit_event(audit_event)
    }

    /// Log scan operation events
    pub async fn log_scan_started(
        &self,
        scan_id: &ScanId,
        scan_type: &str,
        target_paths: &[String],
        user: Option<&str>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let logger = self.core_logger.read().await;
        
        let details = serde_json::json!({
            "scan_type": scan_type,
            "target_paths": target_paths,
            "start_time": Utc::now()
        });

        let mut event = StructuredEvent::new(
            "scan_started",
            EventSeverity::Medium,
            "scan_engine",
            &format!("Scan {} started: {} scan of {} targets", scan_id, scan_type, target_paths.len()),
        )
        .with_details(details)
        .with_correlation_id(&scan_id.to_string());

        if let Some(user) = user {
            event = event.with_user(user);
        }

        logger.log_structured_event(event)?;

        // Log audit event
        let audit_event = AuditEvent {
            event_type: AuditEventType::ScanOperation,
            user: user.unwrap_or("system").to_string(),
            timestamp: Utc::now(),
            resource: format!("scan:{}", scan_id),
            action: "start".to_string(),
            result: AuditResult::Success,
            details: Some(serde_json::json!({
                "scan_type": scan_type,
                "target_count": target_paths.len()
            })),
        };

        logger.log_audit_event(audit_event)
    }

    /// Log scan completion
    pub async fn log_scan_completed(
        &self,
        scan_id: &ScanId,
        files_scanned: u64,
        threats_found: u32,
        duration_ms: u64,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let logger = self.core_logger.read().await;
        
        let details = serde_json::json!({
            "files_scanned": files_scanned,
            "threats_found": threats_found,
            "duration_ms": duration_ms,
            "completion_time": Utc::now()
        });

        let severity = if threats_found > 0 {
            EventSeverity::High
        } else {
            EventSeverity::Medium
        };

        let event = StructuredEvent::new(
            "scan_completed",
            severity,
            "scan_engine",
            &format!(
                "Scan {} completed: {} files scanned, {} threats found in {}ms",
                scan_id, files_scanned, threats_found, duration_ms
            ),
        )
        .with_details(details)
        .with_correlation_id(&scan_id.to_string());

        logger.log_structured_event(event)
    }

    /// Log threat detection with enhanced details
    pub async fn log_threat_detected(
        &self,
        threat_info: &ThreatInfo,
        scan_id: Option<&ScanId>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let logger = self.core_logger.read().await;
        log_structured_threat_event(&logger, threat_info)?;

        // If part of a scan, also log with scan correlation
        if let Some(scan_id) = scan_id {
            let details = serde_json::json!({
                "threat_id": threat_info.id.to_string(),
                "threat_name": threat_info.name,
                "file_path": threat_info.file_path.display().to_string(),
                "scan_context": true
            });

            let event = StructuredEvent::new(
                "scan_threat_detected",
                EventSeverity::High,
                "scan_engine",
                &format!("Threat {} detected during scan {}", threat_info.name, scan_id),
            )
            .with_details(details)
            .with_correlation_id(&scan_id.to_string());

            logger.log_structured_event(event)?;
        }

        Ok(())
    }

    /// Log quarantine operations
    pub async fn log_quarantine_operation(
        &self,
        operation: QuarantineOperation,
        quarantine_id: &QuarantineId,
        file_path: &Path,
        result: &Result<(), AntivirusError>,
        user: Option<&str>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let logger = self.core_logger.read().await;
        log_structured_quarantine_event(&logger, operation.clone(), quarantine_id, file_path, result)?;

        // Log audit event
        let audit_result = if result.is_ok() {
            AuditResult::Success
        } else {
            AuditResult::Failure
        };

        let audit_event = AuditEvent {
            event_type: AuditEventType::QuarantineOperation,
            user: user.unwrap_or("system").to_string(),
            timestamp: Utc::now(),
            resource: file_path.display().to_string(),
            action: format!("{:?}", operation).to_lowercase(),
            result: audit_result,
            details: Some(serde_json::json!({
                "quarantine_id": quarantine_id.to_string(),
                "error": result.as_ref().err().map(|e| e.to_string())
            })),
        };

        logger.log_audit_event(audit_event)
    }

    /// Log update operations
    pub async fn log_update_operation(
        &self,
        operation: &str,
        component: &str,
        version: Option<&str>,
        result: &Result<(), AntivirusError>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let logger = self.core_logger.read().await;
        
        let severity = if result.is_ok() {
            EventSeverity::Medium
        } else {
            EventSeverity::High
        };

        let details = serde_json::json!({
            "component": component,
            "version": version,
            "success": result.is_ok(),
            "error": result.as_ref().err().map(|e| e.to_string()),
            "timestamp": Utc::now()
        });

        let message = match result {
            Ok(()) => format!("Update operation '{}' successful for component '{}'", operation, component),
            Err(e) => format!("Update operation '{}' failed for component '{}': {}", operation, component, e),
        };

        let event = StructuredEvent::new(
            "update_operation",
            severity,
            "update_manager",
            &message,
        )
        .with_details(details.clone());

        logger.log_structured_event(event)?;

        // Log audit event
        let audit_event = AuditEvent {
            event_type: AuditEventType::UpdateOperation,
            user: "system".to_string(),
            timestamp: Utc::now(),
            resource: component.to_string(),
            action: operation.to_string(),
            result: if result.is_ok() { AuditResult::Success } else { AuditResult::Failure },
            details: Some(details),
        };

        logger.log_audit_event(audit_event)
    }

    /// Log policy changes
    pub async fn log_policy_change(
        &self,
        user: &str,
        policy_type: &str,
        changes: &serde_json::Value,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let logger = self.core_logger.read().await;
        
        let event = StructuredEvent::new(
            "policy_change",
            EventSeverity::Medium,
            "policy_manager",
            &format!("Policy '{}' modified by user '{}'", policy_type, user),
        )
        .with_user(user)
        .with_details(changes.clone());

        logger.log_structured_event(event)?;

        // Log audit event
        let audit_event = AuditEvent {
            event_type: AuditEventType::PolicyChange,
            user: user.to_string(),
            timestamp: Utc::now(),
            resource: policy_type.to_string(),
            action: "modify".to_string(),
            result: AuditResult::Success,
            details: Some(changes.clone()),
        };

        logger.log_audit_event(audit_event)
    }

    /// Log authentication events
    pub async fn log_authentication_event(
        &self,
        user: &str,
        action: &str,
        success: bool,
        source_ip: Option<&str>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let logger = self.core_logger.read().await;
        
        let severity = if success {
            EventSeverity::Medium
        } else {
            EventSeverity::High
        };

        let details = serde_json::json!({
            "action": action,
            "success": success,
            "source_ip": source_ip,
            "timestamp": Utc::now()
        });

        let message = if success {
            format!("User '{}' successfully performed '{}'", user, action)
        } else {
            format!("User '{}' failed to perform '{}'", user, action)
        };

        let event = StructuredEvent::new(
            "authentication",
            severity,
            "auth_manager",
            &message,
        )
        .with_user(user)
        .with_details(details);

        logger.log_structured_event(event)?;

        // Log audit event
        let audit_event = AuditEvent {
            event_type: AuditEventType::Authentication,
            user: user.to_string(),
            timestamp: Utc::now(),
            resource: "authentication_system".to_string(),
            action: action.to_string(),
            result: if success { AuditResult::Success } else { AuditResult::Failure },
            details: Some(serde_json::json!({
                "source_ip": source_ip
            })),
        };

        logger.log_audit_event(audit_event)
    }


    pub async fn get_event_statistics(&self) -> std::collections::HashMap<String, u64> {
        let logger = self.core_logger.read().await;
        logger.get_event_statistics()
    }

    pub async fn archive_logs(&self) -> Result<(), Box<dyn std::error::Error>> {
        let logger = self.core_logger.read().await;
        logger.archive_logs()
    }

    pub async fn cleanup_old_logs(&self, days_to_keep: u32) -> Result<(), Box<dyn std::error::Error>> {
        let logger = self.core_logger.read().await;
        logger.cleanup_old_logs(days_to_keep)
    }

    pub async fn log_performance_metrics(
        &self,
        component: &str,
        metrics: &serde_json::Value,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let logger = self.core_logger.read().await;
        
        let event = StructuredEvent::new(
            "performance_metrics",
            EventSeverity::Debug,
            component,
            &format!("Performance metrics for {}", component),
        )
        .with_details(metrics.clone());

        logger.log_structured_event(event)
    }

    pub async fn log_health_check(
        &self,
        component: &str,
        status: &str,
        details: Option<&serde_json::Value>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let logger = self.core_logger.read().await;
        
        let severity = match status {
            "healthy" => EventSeverity::Debug,
            "warning" => EventSeverity::Medium,
            "critical" | "error" => EventSeverity::High,
            _ => EventSeverity::Low,
        };

        let mut event = StructuredEvent::new(
            "health_check",
            severity,
            component,
            &format!("Health check for {}: {}", component, status),
        );

        if let Some(details) = details {
            event = event.with_details(details.clone());
        }

        logger.log_structured_event(event)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use hadron_core::{ThreatType, ThreatSeverity, DetectionMethod};
    use std::path::PathBuf;


    fn create_test_config() -> LoggingConfig {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("test.log");
        
        LoggingConfig {
            log_level: "info".to_string(),
            log_file_path: log_path,
            max_log_file_size_mb: 10,
            max_log_files: 5,
            enable_console_logging: false,
            enable_windows_event_log: false,
            enable_json_logging: true,
        }
    }

    #[tokio::test]
    async fn test_service_event_logger_creation() {
        let config = create_test_config();
        let logger = ServiceEventLogger::new(config, "TestService");
        assert!(logger.is_ok());
    }

    #[tokio::test]
    async fn test_service_startup_logging() {
        let config = create_test_config();
        let logger = ServiceEventLogger::new(config, "TestService").unwrap();
        
        let result = logger.log_service_startup().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_configuration_change_logging() {
        let config = create_test_config();
        let logger = ServiceEventLogger::new(config, "TestService").unwrap();
        
        let result = logger.log_configuration_change(
            "admin",
            "scan_timeout",
            "30",
            "60"
        ).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_scan_operation_logging() {
        let config = create_test_config();
        let logger = ServiceEventLogger::new(config, "TestService").unwrap();
        
        let scan_id = ScanId::from(uuid::Uuid::new_v4());
        let target_paths = vec!["C:\\test".to_string()];
        
        let result = logger.log_scan_started(
            &scan_id,
            "full_scan",
            &target_paths,
            Some("user1")
        ).await;
        assert!(result.is_ok());

        let result = logger.log_scan_completed(&scan_id, 100, 2, 5000).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_threat_detection_logging() {
        let config = create_test_config();
        let logger = ServiceEventLogger::new(config, "TestService").unwrap();
        
        let threat_info = ThreatInfo {
            id: hadron_core::ThreatId::from(uuid::Uuid::new_v4()),
            name: "TestTrojan".to_string(),
            threat_type: ThreatType::Trojan,
            severity: ThreatSeverity::High,
            file_path: PathBuf::from("C:\\malware.exe"),
            file_hash: "abc123".to_string(),
            detection_method: DetectionMethod::Signature,
            timestamp: Utc::now(),
            additional_info: std::collections::HashMap::new(),
        };

        let scan_id = ScanId::from(uuid::Uuid::new_v4());
        let result = logger.log_threat_detected(&threat_info, Some(&scan_id)).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_authentication_logging() {
        let config = create_test_config();
        let logger = ServiceEventLogger::new(config, "TestService").unwrap();
        
        let result = logger.log_authentication_event(
            "admin",
            "login",
            true,
            Some("192.168.1.100")
        ).await;
        assert!(result.is_ok());

        let result = logger.log_authentication_event(
            "user1",
            "change_settings",
            false,
            None
        ).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_performance_metrics_logging() {
        let config = create_test_config();
        let logger = ServiceEventLogger::new(config, "TestService").unwrap();
        
        let metrics = serde_json::json!({
            "cpu_usage": 25.5,
            "memory_usage": 512,
            "scan_rate": 1000
        });

        let result = logger.log_performance_metrics("scan_engine", &metrics).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_health_check_logging() {
        let config = create_test_config();
        let logger = ServiceEventLogger::new(config, "TestService").unwrap();
        
        let details = serde_json::json!({
            "uptime": 3600,
            "last_update": "2024-01-01T00:00:00Z"
        });

        let result = logger.log_health_check("scan_engine", "healthy", Some(&details)).await;
        assert!(result.is_ok());

        let result = logger.log_health_check("update_manager", "warning", None).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_event_statistics() {
        let config = create_test_config();
        let logger = ServiceEventLogger::new(config, "TestService").unwrap();
        
        let _ = logger.log_service_startup().await;
        let _ = logger.log_service_startup().await;
        
        let stats = logger.get_event_statistics().await;
        assert!(stats.contains_key("service_startup"));
    }
}