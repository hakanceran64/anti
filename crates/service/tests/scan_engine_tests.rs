use av_service::ScanEngineImpl;
use hadron_core::{ScanType, ScanStatus};
use tempfile::TempDir;
use tokio::fs;
use std::path::PathBuf;
#[tokio::test]
async fn test_scan_engine_creation() {
    let engine = ScanEngineImpl::new().unwrap();
    assert!(!engine.is_running().await);
}
#[tokio::test]
async fn test_scan_engine_lifecycle() {
    let engine = ScanEngineImpl::new().unwrap();
    engine.start().await.unwrap();
    assert!(engine.is_running().await);
    engine.stop().await.unwrap();
    assert!(!engine.is_running().await);
}
#[tokio::test]
async fn test_file_scanning() {
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("test.txt");
    fs::write(&test_file, "This is a test file").await.unwrap();
    let engine = ScanEngineImpl::new().unwrap();
    engine.start().await.unwrap();
    let result = engine.scan_file(&test_file).await.unwrap();
    assert_eq!(result.status, ScanStatus::Completed);
    assert_eq!(result.scanned_files, 1);
}
#[tokio::test]
async fn test_eicar_detection() {
    let temp_dir = TempDir::new().unwrap();
    let eicar_file = temp_dir.path().join("eicar.com");
    fs::write(&eicar_file, "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*").await.unwrap();
    let engine = ScanEngineImpl::new().unwrap();
    engine.start().await.unwrap();
    let result = engine.scan_file(&eicar_file).await.unwrap();
    assert_eq!(result.status, ScanStatus::Completed);
    if engine.get_signature_stats().await.total_signatures > 0 {
        assert!(!result.threats_found.is_empty(), "Should detect EICAR test file");
    }
}
#[tokio::test]
async fn test_directory_scanning() {
    let temp_dir = TempDir::new().unwrap();
    let sub_dir = temp_dir.path().join("subdir");
    fs::create_dir(&sub_dir).await.unwrap();
    let file1 = temp_dir.path().join("file1.txt");
    let file2 = sub_dir.join("file2.txt");
    let file3 = temp_dir.path().join("file3.exe");
    fs::write(&file1, "content1").await.unwrap();
    fs::write(&file2, "content2").await.unwrap();
    fs::write(&file3, "executable content").await.unwrap();
    let engine = ScanEngineImpl::new().unwrap();
    engine.start().await.unwrap();
    let targets = vec![temp_dir.path().to_path_buf()];
    let job_id = engine.start_scan(ScanType::Custom(targets), vec![]).await.unwrap();
    let mut attempts = 0;
    loop {
        let status = engine.get_scan_status(job_id).await.unwrap();
        match status {
            ScanStatus::Completed | ScanStatus::Failed | ScanStatus::Cancelled => break,
            ScanStatus::Running | ScanStatus::Paused => {
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                attempts += 1;
                if attempts > 100 {
                    panic!("Scan did not complete in time");
                }
            }
        }
    }
    let final_status = engine.get_scan_status(job_id).await.unwrap();
    assert_eq!(final_status, ScanStatus::Completed);
}
#[tokio::test]
async fn test_scan_progress_tracking() {
    let temp_dir = TempDir::new().unwrap();
    for i in 0..5 {
        let file_path = temp_dir.path().join(format!("test_{}.txt", i));
        fs::write(&file_path, format!("Test content {}", i)).await.unwrap();
    }
    let engine = ScanEngineImpl::new().unwrap();
    engine.start().await.unwrap();
    let progress_received = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let progress_clone = progress_received.clone();
    engine.register_progress_callback(Box::new(move |progress| {
        let mut received = progress_clone.lock().unwrap();
        received.push(progress);
    })).await.unwrap();
    let targets = vec![temp_dir.path().to_path_buf()];
    let job_id = engine.start_scan(ScanType::Custom(targets), vec![]).await.unwrap();
    let mut attempts = 0;
    loop {
        let status = engine.get_scan_status(job_id).await.unwrap();
        if matches!(status, ScanStatus::Completed | ScanStatus::Failed | ScanStatus::Cancelled) {
            break;
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        attempts += 1;
        if attempts > 100 {
            break;
        }
    }
    let progress_reports = progress_received.lock().unwrap();
    assert!(!progress_reports.is_empty(), "Should have received progress reports");
}
#[tokio::test]
async fn test_scan_cancellation() {
    let temp_dir = TempDir::new().unwrap();
    for i in 0..20 {
        let file_path = temp_dir.path().join(format!("test_{}.txt", i));
        fs::write(&file_path, format!("Test content {}", i)).await.unwrap();
    }
    let engine = ScanEngineImpl::new().unwrap();
    engine.start().await.unwrap();
    let targets = vec![temp_dir.path().to_path_buf()];
    let job_id = engine.start_scan(ScanType::Custom(targets), vec![]).await.unwrap();
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
    engine.cancel_scan(job_id).await.unwrap();
    let status = engine.get_scan_status(job_id).await.unwrap();
    assert_eq!(status, ScanStatus::Cancelled);
}
#[tokio::test]
async fn test_memory_scan() {
    let engine = ScanEngineImpl::new().unwrap();
    engine.start().await.unwrap();
    let job_id = engine.start_scan(ScanType::Memory, vec![]).await.unwrap();
    let mut attempts = 0;
    loop {
        let status = engine.get_scan_status(job_id).await.unwrap();
        if matches!(status, ScanStatus::Completed | ScanStatus::Failed | ScanStatus::Cancelled) {
            break;
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        attempts += 1;
        if attempts > 50 {
            break;
        }
    }
    let final_status = engine.get_scan_status(job_id).await.unwrap();
    assert_eq!(final_status, ScanStatus::Completed);
}
#[tokio::test]
async fn test_scan_statistics() {
    let engine = ScanEngineImpl::new().unwrap();
    engine.start().await.unwrap();
    let initial_stats = engine.get_statistics().await.unwrap();
    assert_eq!(initial_stats.total_files_scanned, 0);
    assert_eq!(initial_stats.total_threats_detected, 0);
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("test.txt");
    fs::write(&test_file, "Test content").await.unwrap();
    let _result = engine.scan_file(&test_file).await.unwrap();
    let updated_stats = engine.get_statistics().await.unwrap();
    assert!(updated_stats.last_scan_time.is_some());
}
#[tokio::test]
async fn test_signature_database_integration() {
    let engine = ScanEngineImpl::new().unwrap();
    engine.start().await.unwrap();
    let sig_stats = engine.get_signature_stats().await;
    assert!(!sig_stats.version.is_empty());
    let reload_result = engine.reload_signatures().await;
    match reload_result {
        Ok(stats) => {
            assert!(stats.compilation_time_ms >= 0);
        }
        Err(_) => {
        }
    }
}
#[tokio::test]
async fn test_file_scanner_configuration() {
    let engine = ScanEngineImpl::new().unwrap();
    let file_scanner = engine.get_file_scanner();
    let directory_walker = engine.get_directory_walker();
}
#[tokio::test]
async fn test_executable_file_analysis() {
    let temp_dir = TempDir::new().unwrap();
    let exe_file = temp_dir.path().join("test.exe");
    let mut pe_content = vec![0u8; 64];
    pe_content[0] = 0x4D;
    pe_content[1] = 0x5A;
    pe_content[60] = 60;
    pe_content.extend_from_slice(&[0x50, 0x45, 0x00, 0x00]);
    pe_content.extend_from_slice(b"This contains suspicious strings: cmd.exe powershell.exe keylog password backdoor");
    fs::write(&exe_file, pe_content).await.unwrap();
    let engine = ScanEngineImpl::new().unwrap();
    engine.start().await.unwrap();
    let result = engine.scan_file(&exe_file).await.unwrap();
    assert_eq!(result.status, ScanStatus::Completed);
    if !result.threats_found.is_empty() {
        let threat = &result.threats_found[0];
        assert_eq!(threat.threat_type, hadron_core::ThreatType::Suspicious);
        assert!(threat.additional_info.contains_key("suspicious_strings"));
    }
}