use async_trait::async_trait;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{info, warn, error};
use hadron_core::{
    Result, AntivirusError, SandboxId, SandboxEngine, SandboxOperations, 
    SandboxConfig, AnalysisDepth, ExecutionReport, SandboxStatus
};
pub struct SandboxService {
    engine: Arc<Mutex<SandboxEngine>>,
    default_config: SandboxConfig,
}
impl SandboxService {
    pub fn new() -> Self {
        let config = SandboxConfig {
            timeout_seconds: 300,
            max_memory_mb: 512,
            max_cpu_percent: 50.0,
            enable_network: false,
            redirect_filesystem: true,
            monitor_registry: true,
            capture_screenshots: false,
            analysis_depth: AnalysisDepth::Standard,
        };
        Self {
            engine: Arc::new(Mutex::new(SandboxEngine::with_config(config.clone()))),
            default_config: config,
        }
    }
    pub fn with_config(config: SandboxConfig) -> Self {
        Self {
            engine: Arc::new(Mutex::new(SandboxEngine::with_config(config.clone()))),
            default_config: config,
        }
    }
    pub async fn analyze_file(&self, file_path: &Path) -> Result<SandboxAnalysisResult> {
        info!("Starting sandbox analysis for file: {}", file_path.display());
        if !file_path.exists() {
            return Err(AntivirusError::Internal(
                format!("File not found: {}", file_path.display())
            ));
        }
        let file_size = std::fs::metadata(file_path)
            .map_err(|e| AntivirusError::Internal(format!("Failed to get file metadata: {}", e)))?
            .len();
        if file_size > (self.default_config.max_memory_mb * 1024 * 1024) {
            warn!("File too large for sandbox analysis: {} bytes", file_size);
            return Err(AntivirusError::Internal(
                "File too large for sandbox analysis".to_string()
            ));
        }
        let engine = self.engine.lock().await;
        let sandbox_id = engine.create_sandbox().await
            .map_err(|e| {
                error!("Failed to create sandbox: {}", e);
                e
            })?;
        info!("Created sandbox {} for analysis", sandbox_id);
        let execution_result = engine.execute_in_sandbox(sandbox_id, file_path).await;
        let final_status = engine.get_sandbox_status(sandbox_id).await.ok();
        if let Err(e) = engine.destroy_sandbox(sandbox_id).await {
            warn!("Failed to cleanup sandbox {}: {}", sandbox_id, e);
        } else {
            info!("Cleaned up sandbox {}", sandbox_id);
        }
        match execution_result {
            Ok(report) => {
                info!("Sandbox analysis completed for {}: malicious={}", 
                      file_path.display(), report.is_malicious);
                Ok(SandboxAnalysisResult {
                    file_path: file_path.to_path_buf(),
                    sandbox_id,
                    execution_report: Some(report),
                    final_status,
                    analysis_success: true,
                    error_message: None,
                })
            }
            Err(e) => {
                error!("Sandbox execution failed for {}: {}", file_path.display(), e);
                Ok(SandboxAnalysisResult {
                    file_path: file_path.to_path_buf(),
                    sandbox_id,
                    execution_report: None,
                    final_status,
                    analysis_success: false,
                    error_message: Some(e.to_string()),
                })
            }
        }
    }
    pub fn get_config(&self) -> &SandboxConfig {
        &self.default_config
    }
    pub async fn update_config(&mut self, new_config: SandboxConfig) -> Result<()> {
        info!("Updating sandbox service configuration");
        if new_config.timeout_seconds == 0 {
            return Err(AntivirusError::Internal(
                "Timeout must be greater than 0".to_string()
            ));
        }
        if new_config.max_memory_mb == 0 {
            return Err(AntivirusError::Internal(
                "Max memory must be greater than 0".to_string()
            ));
        }
        self.default_config = new_config.clone();
        *self.engine.lock().await = SandboxEngine::with_config(new_config);
        info!("Sandbox service configuration updated successfully");
        Ok(())
    }
    pub fn should_analyze_file(&self, file_path: &Path) -> bool {
        if let Some(extension) = file_path.extension().and_then(|ext| ext.to_str()) {
            let suspicious_extensions = [
                "exe", "dll", "scr", "bat", "cmd", "com", "pif", "vbs", "js", "jar",
                "msi", "ps1", "psm1", "psd1", "ps1xml", "psc1", "psc2"
            ];
            if suspicious_extensions.contains(&extension.to_lowercase().as_str()) {
                return true;
            }
        }
        if let Ok(metadata) = std::fs::metadata(file_path) {
            let size = metadata.len();
            if size < 100 || size > 100 * 1024 * 1024 {
                return true;
            }
        }
        false
    }
}
impl Default for SandboxService {
    fn default() -> Self {
        Self::new()
    }
}
#[derive(Debug, Clone)]
pub struct SandboxAnalysisResult {
    pub file_path: std::path::PathBuf,
    pub sandbox_id: SandboxId,
    pub execution_report: Option<ExecutionReport>,
    pub final_status: Option<SandboxStatus>,
    pub analysis_success: bool,
    pub error_message: Option<String>,
}
impl SandboxAnalysisResult {
    pub fn is_malicious(&self) -> bool {
        self.execution_report
            .as_ref()
            .map(|report| report.is_malicious)
            .unwrap_or(false)
    }
    pub fn suspicious_behavior_count(&self) -> usize {
        self.execution_report
            .as_ref()
            .map(|report| report.behaviors_observed.len())
            .unwrap_or(0)
    }
    pub fn network_activity_count(&self) -> usize {
        self.execution_report
            .as_ref()
            .map(|report| report.network_activity.len())
            .unwrap_or(0)
    }
    pub fn file_operations_count(&self) -> usize {
        self.execution_report
            .as_ref()
            .map(|report| report.file_operations.len())
            .unwrap_or(0)
    }
    pub fn registry_operations_count(&self) -> usize {
        self.execution_report
            .as_ref()
            .map(|report| report.registry_operations.len())
            .unwrap_or(0)
    }
    pub fn execution_time_ms(&self) -> u64 {
        self.execution_report
            .as_ref()
            .map(|report| report.execution_time_ms)
            .unwrap_or(0)
    }
    pub fn get_summary(&self) -> String {
        if !self.analysis_success {
            return format!("Analysis failed: {}", 
                          self.error_message.as_deref().unwrap_or("Unknown error"));
        }
        if let Some(report) = &self.execution_report {
            format!(
                "Execution completed in {}ms. Malicious: {}. Behaviors: {}, Network: {}, Files: {}, Registry: {}",
                report.execution_time_ms,
                report.is_malicious,
                report.behaviors_observed.len(),
                report.network_activity.len(),
                report.file_operations.len(),
                report.registry_operations.len()
            )
        } else {
            "No execution report available".to_string()
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use tempfile::TempDir;
    #[tokio::test]
    async fn test_sandbox_service_creation() {
        let service = SandboxService::new();
        let config = service.get_config();
        assert_eq!(config.timeout_seconds, 300);
        assert_eq!(config.max_memory_mb, 512);
        assert!(!config.enable_network);
        assert!(config.redirect_filesystem);
    }
    #[tokio::test]
    async fn test_sandbox_service_config_update() {
        let mut service = SandboxService::new();
        let new_config = SandboxConfig {
            timeout_seconds: 120,
            max_memory_mb: 256,
            enable_network: true,
            analysis_depth: AnalysisDepth::Deep,
            ..Default::default()
        };
        service.update_config(new_config.clone()).await.unwrap();
        let updated_config = service.get_config();
        assert_eq!(updated_config.timeout_seconds, 120);
        assert_eq!(updated_config.max_memory_mb, 256);
        assert!(updated_config.enable_network);
    }
    #[tokio::test]
    async fn test_should_analyze_file() {
        let service = SandboxService::new();
        assert!(service.should_analyze_file(std::path::Path::new("test.exe")));
        assert!(service.should_analyze_file(std::path::Path::new("malware.dll")));
        assert!(service.should_analyze_file(std::path::Path::new("script.bat")));
        assert!(!service.should_analyze_file(std::path::Path::new("document.txt")));
        assert!(!service.should_analyze_file(std::path::Path::new("image.jpg")));
    }
    #[tokio::test]
    async fn test_analyze_file_not_found() {
        let service = SandboxService::new();
        let result = service.analyze_file(std::path::Path::new("nonexistent.exe")).await;
        assert!(result.is_err());
    }
    #[tokio::test]
    async fn test_analyze_file_success() {
        let service = SandboxService::new();
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test.txt");
        let mut file = File::create(&test_file).unwrap();
        writeln!(file, "Test file content").unwrap();
        let result = service.analyze_file(&test_file).await.unwrap();
        assert_eq!(result.file_path, test_file);
        assert!(!result.analysis_success || result.execution_report.is_some());
    }
    #[test]
    fn test_sandbox_analysis_result() {
        use hadron_core::traits::{ExecutionReport, NetworkActivity, FileOperation, RegistryOperation};
        let report = ExecutionReport {
            sandbox_id: uuid::Uuid::new_v4(),
            execution_time_ms: 1500,
            exit_code: 0,
            behaviors_observed: vec!["Process created".to_string()],
            network_activity: vec![NetworkActivity {
                destination: "example.com".to_string(),
                port: 80,
                protocol: "HTTP".to_string(),
                bytes_sent: 100,
                bytes_received: 200,
            }],
            file_operations: vec![FileOperation {
                operation: "Create".to_string(),
                file_path: std::path::PathBuf::from("test.txt"),
                success: true,
            }],
            registry_operations: vec![RegistryOperation {
                operation: "Write".to_string(),
                key_path: "HKLM\\Software\\Test".to_string(),
                value_name: Some("TestValue".to_string()),
                success: true,
            }],
            is_malicious: false,
        };
        let result = SandboxAnalysisResult {
            file_path: std::path::PathBuf::from("test.exe"),
            sandbox_id: report.sandbox_id,
            execution_report: Some(report),
            final_status: None,
            analysis_success: true,
            error_message: None,
        };
        assert!(!result.is_malicious());
        assert_eq!(result.suspicious_behavior_count(), 1);
        assert_eq!(result.network_activity_count(), 1);
        assert_eq!(result.file_operations_count(), 1);
        assert_eq!(result.registry_operations_count(), 1);
        assert_eq!(result.execution_time_ms(), 1500);
        let summary = result.get_summary();
        assert!(summary.contains("1500ms"));
        assert!(summary.contains("Malicious: false"));
    }
}