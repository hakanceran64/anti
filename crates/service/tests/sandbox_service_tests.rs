use av_service::sandbox_service::{SandboxService, SandboxAnalysisResult};
use hadron_core::{SandboxConfig, AnalysisDepth};
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
    assert!(result.analysis_success || result.error_message.is_some());
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
#[tokio::test]
async fn test_config_validation() {
    let mut service = SandboxService::new();
    let invalid_config = SandboxConfig {
        timeout_seconds: 0,
        ..Default::default()
    };
    let result = service.update_config(invalid_config).await;
    assert!(result.is_err());
    let invalid_config = SandboxConfig {
        max_memory_mb: 0,
        ..Default::default()
    };
    let result = service.update_config(invalid_config).await;
    assert!(result.is_err());
}
#[tokio::test]
async fn test_file_size_limits() {
    let service = SandboxService::new();
    let temp_dir = TempDir::new().unwrap();
    let large_file = temp_dir.path().join("large.bin");
    let mut file = File::create(&large_file).unwrap();
    let large_data = vec![0u8; 1024 * 1024];
    for _ in 0..600 {
        file.write_all(&large_data).unwrap();
    }
    file.flush().unwrap();
    drop(file);
    let result = service.analyze_file(&large_file).await;
    assert!(result.is_err());
}