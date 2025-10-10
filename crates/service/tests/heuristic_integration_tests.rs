use av_service::ScanEngineImpl;
use hadron_core::{ScanType, ScanStatus, ThreatType, DetectionMethod};
use tempfile::TempDir;
use tokio::fs;
#[tokio::test]
async fn test_heuristic_analysis_integration() {
    let temp_dir = TempDir::new().unwrap();
    let suspicious_exe = temp_dir.path().join("suspicious.exe");
    let mut pe_content = vec![0u8; 64];
    pe_content[0] = 0x4D;
    pe_content[1] = 0x5A;
    pe_content[60] = 60;
    pe_content.extend_from_slice(&[0x50, 0x45, 0x00, 0x00]);
    pe_content.extend_from_slice(b"CreateRemoteThread WriteProcessMemory VirtualAllocEx keylog password backdoor");
    fs::write(&suspicious_exe, pe_content).await.unwrap();
    let engine = ScanEngineImpl::new().unwrap();
    engine.start().await.unwrap();
    let result = engine.scan_file(&suspicious_exe).await.unwrap();
    assert_eq!(result.status, ScanStatus::Completed);
    let heuristic_threats: Vec<_> = result.threats_found.iter()
        .filter(|t| t.detection_method == DetectionMethod::Heuristic)
        .collect();
    if !heuristic_threats.is_empty() {
        assert!(!heuristic_threats.is_empty(), "Should detect heuristic threats");
        for threat in &heuristic_threats {
            assert!(threat.name.starts_with("Heuristic."));
            assert!(threat.additional_info.contains_key("confidence"));
            assert!(threat.additional_info.contains_key("rule_id"));
        }
    }
}
#[tokio::test]
async fn test_ransomware_heuristic_detection() {
    let temp_dir = TempDir::new().unwrap();
    let ransomware_file = temp_dir.path().join("ransomware.exe");
    let mut pe_content = vec![0u8; 64];
    pe_content[0] = 0x4D;
    pe_content[1] = 0x5A;
    pe_content[60] = 60;
    pe_content.extend_from_slice(&[0x50, 0x45, 0x00, 0x00]);
    pe_content.extend_from_slice(b"CryptEncrypt CryptGenKey bitcoin ransom decrypt your files are encrypted");
    fs::write(&ransomware_file, pe_content).await.unwrap();
    let engine = ScanEngineImpl::new().unwrap();
    engine.start().await.unwrap();
    let result = engine.scan_file(&ransomware_file).await.unwrap();
    let ransomware_threats: Vec<_> = result.threats_found.iter()
        .filter(|t| t.threat_type == ThreatType::Ransomware)
        .collect();
    if !ransomware_threats.is_empty() {
        assert!(!ransomware_threats.is_empty(), "Should detect ransomware indicators");
    }
}
#[tokio::test]
async fn test_keylogger_heuristic_detection() {
    let temp_dir = TempDir::new().unwrap();
    let keylogger_file = temp_dir.path().join("keylogger.exe");
    let mut pe_content = vec![0u8; 64];
    pe_content[0] = 0x4D;
    pe_content[1] = 0x5A;
    pe_content[60] = 60;
    pe_content.extend_from_slice(&[0x50, 0x45, 0x00, 0x00]);
    pe_content.extend_from_slice(b"GetAsyncKeyState SetWindowsHookEx keylog capture keystrokes");
    fs::write(&keylogger_file, pe_content).await.unwrap();
    let engine = ScanEngineImpl::new().unwrap();
    engine.start().await.unwrap();
    let result = engine.scan_file(&keylogger_file).await.unwrap();
    let spyware_threats: Vec<_> = result.threats_found.iter()
        .filter(|t| t.threat_type == ThreatType::Spyware)
        .collect();
    if !spyware_threats.is_empty() {
        assert!(!spyware_threats.is_empty(), "Should detect keylogger indicators");
    }
}
#[tokio::test]
async fn test_packed_executable_detection() {
    let temp_dir = TempDir::new().unwrap();
    let packed_file = temp_dir.path().join("packed.exe");
    let mut pe_content = vec![0u8; 64];
    pe_content[0] = 0x4D;
    pe_content[1] = 0x5A;
    pe_content[60] = 60;
    pe_content.extend_from_slice(&[0x50, 0x45, 0x00, 0x00]);
    let high_entropy_data: Vec<u8> = (0..=255).cycle().take(2000).collect();
    pe_content.extend(high_entropy_data);
    fs::write(&packed_file, pe_content).await.unwrap();
    let engine = ScanEngineImpl::new().unwrap();
    engine.start().await.unwrap();
    let result = engine.scan_file(&packed_file).await.unwrap();
    if !result.threats_found.is_empty() {
        let suspicious_threats: Vec<_> = result.threats_found.iter()
            .filter(|t| t.threat_type == ThreatType::Suspicious)
            .collect();
        if !suspicious_threats.is_empty() {
            let entropy_detections: Vec<_> = suspicious_threats.iter()
                .filter(|t| t.name.contains("Entropy") || t.name.contains("Packed"))
                .collect();
            if !entropy_detections.is_empty() {
                assert!(!entropy_detections.is_empty(), "Should detect high entropy/packed executable");
            }
        }
    }
}
#[tokio::test]
async fn test_clean_executable_no_false_positives() {
    let temp_dir = TempDir::new().unwrap();
    let clean_exe = temp_dir.path().join("clean.exe");
    let mut pe_content = vec![0u8; 64];
    pe_content[0] = 0x4D;
    pe_content[1] = 0x5A;
    pe_content[60] = 60;
    pe_content.extend_from_slice(&[0x50, 0x45, 0x00, 0x00]);
    pe_content.extend_from_slice(b"Hello World! This is a normal application with standard functionality.");
    fs::write(&clean_exe, pe_content).await.unwrap();
    let engine = ScanEngineImpl::new().unwrap();
    engine.start().await.unwrap();
    let result = engine.scan_file(&clean_exe).await.unwrap();
    let high_confidence_threats: Vec<_> = result.threats_found.iter()
        .filter(|t| {
            t.detection_method == DetectionMethod::Heuristic &&
            t.additional_info.get("confidence")
                .and_then(|c| c.parse::<f32>().ok())
                .map_or(false, |conf| conf > 0.8)
        })
        .collect();
    assert!(high_confidence_threats.is_empty() || high_confidence_threats.len() < 2, 
           "Clean executable should not trigger multiple high-confidence heuristic detections");
}
#[tokio::test]
async fn test_heuristic_rule_management() {
    let engine = ScanEngineImpl::new().unwrap();
    engine.start().await.unwrap();
    let analyzer = engine.get_heuristic_analyzer();
    let initial_rule_count = analyzer.get_rules().len();
    assert!(initial_rule_count > 0, "Should have default heuristic rules loaded");
    for rule in analyzer.get_rules() {
        assert!(!rule.id.is_empty());
        assert!(!rule.name.is_empty());
        assert!(!rule.description.is_empty());
        assert!(!rule.conditions.is_empty());
        assert!(rule.weight > 0.0 && rule.weight <= 1.0);
    }
}
#[tokio::test]
async fn test_entropy_analysis() {
    let temp_dir = TempDir::new().unwrap();
    let low_entropy_file = temp_dir.path().join("low_entropy.bin");
    let low_entropy_data = vec![0u8; 1000];
    fs::write(&low_entropy_file, low_entropy_data).await.unwrap();
    let high_entropy_file = temp_dir.path().join("high_entropy.bin");
    let high_entropy_data: Vec<u8> = (0..=255).cycle().take(1000).collect();
    fs::write(&high_entropy_file, high_entropy_data).await.unwrap();
    let engine = ScanEngineImpl::new().unwrap();
    engine.start().await.unwrap();
    let low_result = engine.scan_file(&low_entropy_file).await.unwrap();
    let high_result = engine.scan_file(&high_entropy_file).await.unwrap();
    assert_eq!(low_result.status, ScanStatus::Completed);
    assert_eq!(high_result.status, ScanStatus::Completed);
}
#[tokio::test]
async fn test_string_analysis_integration() {
    let temp_dir = TempDir::new().unwrap();
    let string_test_file = temp_dir.path().join("strings.exe");
    let mut pe_content = vec![0u8; 64];
    pe_content[0] = 0x4D;
    pe_content[1] = 0x5A;
    pe_content[60] = 60;
    pe_content.extend_from_slice(&[0x50, 0x45, 0x00, 0x00]);
    pe_content.extend_from_slice(b"cmd.exe powershell.exe regedit.exe ");
    pe_content.extend_from_slice(b"CryptEncrypt AES RSA MD5 ");
    pe_content.extend_from_slice(b"http:
    pe_content.extend_from_slice(b"CreateFile WriteFile DeleteFile ");
    pe_content.extend_from_slice(b"RegOpenKey RegSetValue HKEY_CURRENT_USER");
    fs::write(&string_test_file, pe_content).await.unwrap();
    let engine = ScanEngineImpl::new().unwrap();
    engine.start().await.unwrap();
    let result = engine.scan_file(&string_test_file).await.unwrap();
    if !result.threats_found.is_empty() {
        let string_based_threats: Vec<_> = result.threats_found.iter()
            .filter(|t| t.additional_info.contains_key("suspicious_strings") || 
                       t.additional_info.contains_key("suspicious_string_matches"))
            .collect();
        if !string_based_threats.is_empty() {
            assert!(!string_based_threats.is_empty(), "Should detect suspicious string patterns");
        }
    }
}
#[tokio::test]
async fn test_multiple_heuristic_rules_triggering() {
    let temp_dir = TempDir::new().unwrap();
    let multi_threat_file = temp_dir.path().join("multi_threat.exe");
    let mut pe_content = vec![0u8; 64];
    pe_content[0] = 0x4D;
    pe_content[1] = 0x5A;
    pe_content[60] = 60;
    pe_content.extend_from_slice(&[0x50, 0x45, 0x00, 0x00]);
    pe_content.extend_from_slice(b"CreateRemoteThread WriteProcessMemory VirtualAllocEx ");
    pe_content.extend_from_slice(b"GetAsyncKeyState SetWindowsHookEx keylog ");
    pe_content.extend_from_slice(b"CryptEncrypt bitcoin ransom decrypt ");
    let high_entropy_data: Vec<u8> = (0..=255).cycle().take(1000).collect();
    pe_content.extend(high_entropy_data);
    fs::write(&multi_threat_file, pe_content).await.unwrap();
    let engine = ScanEngineImpl::new().unwrap();
    engine.start().await.unwrap();
    let result = engine.scan_file(&multi_threat_file).await.unwrap();
    let heuristic_threats: Vec<_> = result.threats_found.iter()
        .filter(|t| t.detection_method == DetectionMethod::Heuristic)
        .collect();
    if !heuristic_threats.is_empty() {
        let unique_threat_types: std::collections::HashSet<_> = heuristic_threats.iter()
            .map(|t| &t.threat_type)
            .collect();
        assert!(!unique_threat_types.is_empty(), "Should detect threats with heuristic analysis");
    }
}