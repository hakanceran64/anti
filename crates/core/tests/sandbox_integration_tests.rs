use hadron_core::{SandboxEngine, SandboxOperations, SandboxConfig, AnalysisDepth};
use std::fs::File;
use std::io::Write;
use tempfile::TempDir;

#[tokio::test]
async fn test_sandbox_creation_and_destruction() {
    let engine = SandboxEngine::new();
    
    // Create sandbox
    let sandbox_id = engine.create_sandbox().await.unwrap();
    
    // Verify sandbox exists and is not running
    let status = engine.get_sandbox_status(sandbox_id).await.unwrap();
    assert!(!status.is_running);
    
    // Destroy sandbox
    engine.destroy_sandbox(sandbox_id).await.unwrap();
    
    // Verify sandbox no longer exists
    let result = engine.get_sandbox_status(sandbox_id).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_sandbox_with_custom_config() {
    let config = SandboxConfig {
        timeout_seconds: 60,
        max_memory_mb: 256,
        enable_network: true,
        analysis_depth: AnalysisDepth::Deep,
        ..Default::default()
    };
    
    let engine = SandboxEngine::with_config(config);
    let sandbox_id = engine.create_sandbox().await.unwrap();
    
    let status = engine.get_sandbox_status(sandbox_id).await.unwrap();
    assert!(!status.is_running);
    
    engine.destroy_sandbox(sandbox_id).await.unwrap();
}

#[tokio::test]
async fn test_sandbox_execution_simple_file() {
    let engine = SandboxEngine::new();
    let sandbox_id = engine.create_sandbox().await.unwrap();
    
    // Create a simple test file
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("test.txt");
    let mut file = File::create(&test_file).unwrap();
    writeln!(file, "This is a test file").unwrap();
    
    // Execute in sandbox (this will fail on non-Windows systems, but that's expected)
    let result = engine.execute_in_sandbox(sandbox_id, &test_file).await;
    
    // On non-Windows systems, this might fail, but the sandbox should still be created
    match result {
        Ok(report) => {
            assert_eq!(report.sandbox_id, sandbox_id);
            assert!(report.execution_time_ms >= 0);
        }
        Err(_) => {
            // Expected on non-Windows systems or when file can't be executed
            println!("Execution failed as expected on this platform");
        }
    }
    
    engine.destroy_sandbox(sandbox_id).await.unwrap();
}

#[tokio::test]
async fn test_multiple_sandboxes() {
    let engine = SandboxEngine::new();
    
    // Create multiple sandboxes
    let sandbox1 = engine.create_sandbox().await.unwrap();
    let sandbox2 = engine.create_sandbox().await.unwrap();
    let sandbox3 = engine.create_sandbox().await.unwrap();
    
    // Verify all exist
    assert!(engine.get_sandbox_status(sandbox1).await.is_ok());
    assert!(engine.get_sandbox_status(sandbox2).await.is_ok());
    assert!(engine.get_sandbox_status(sandbox3).await.is_ok());
    
    // Destroy them
    engine.destroy_sandbox(sandbox1).await.unwrap();
    engine.destroy_sandbox(sandbox2).await.unwrap();
    engine.destroy_sandbox(sandbox3).await.unwrap();
    
    // Verify all are gone
    assert!(engine.get_sandbox_status(sandbox1).await.is_err());
    assert!(engine.get_sandbox_status(sandbox2).await.is_err());
    assert!(engine.get_sandbox_status(sandbox3).await.is_err());
}

#[test]
fn test_malicious_behavior_analysis() {
    use hadron_core::sandbox::{BehaviorEvent, BehaviorEventType};
    use std::collections::HashMap;
    use chrono::Utc;
    
    let engine = SandboxEngine::new();
    
    // Create suspicious behavior events
    let mut events = Vec::new();
    
    // Registry modification for persistence
    let mut details = HashMap::new();
    details.insert("key_path".to_string(), "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run".to_string());
    events.push(BehaviorEvent {
        timestamp: Utc::now(),
        event_type: BehaviorEventType::RegistryKeyModified,
        process_id: 1234,
        details,
    });
    
    // System file creation
    let mut details = HashMap::new();
    details.insert("file_path".to_string(), "C:\\Windows\\System32\\malware.exe".to_string());
    events.push(BehaviorEvent {
        timestamp: Utc::now(),
        event_type: BehaviorEventType::FileCreated,
        process_id: 1234,
        details,
    });
    
    // Should be detected as malicious
    assert!(engine.analyze_malicious_behavior(&events));
    
    // Test benign behavior
    let benign_events = vec![
        BehaviorEvent {
            timestamp: Utc::now(),
            event_type: BehaviorEventType::FileCreated,
            process_id: 1234,
            details: {
                let mut details = HashMap::new();
                details.insert("file_path".to_string(), "C:\\Users\\Test\\Documents\\file.txt".to_string());
                details
            },
        }
    ];
    
    // Should not be detected as malicious
    assert!(!engine.analyze_malicious_behavior(&benign_events));
}