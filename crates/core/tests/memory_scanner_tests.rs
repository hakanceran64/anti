use hadron_core::{
    MemoryScanner, MemorySignature, ThreatInfo, ThreatType, ThreatSeverity, DetectionMethod
};
use std::path::PathBuf;

#[tokio::test]
async fn test_memory_scanner_basic_functionality() {
    let mut scanner = MemoryScanner::new();
    
    // Test scanner creation
    assert_eq!(scanner.signature_patterns.len(), 0);
    assert_eq!(scanner.rootkit_detectors.len(), 6);
    
    // Add a test signature
    let threat_info = ThreatInfo::new(
        "Test Memory Threat".to_string(),
        ThreatType::Virus,
        ThreatSeverity::High,
        PathBuf::from("memory://test"),
        "a".repeat(64),
        DetectionMethod::Signature,
    ).unwrap();
    
    let signature = MemorySignature {
        id: "test_memory_sig".to_string(),
        pattern: vec![0x4D, 0x5A], // MZ header
        mask: vec![0xFF, 0xFF],
        threat_info,
        min_offset: 0,
        max_offset: Some(1024),
    };
    
    scanner.add_signature(signature);
    assert_eq!(scanner.signature_patterns.len(), 1);
}

#[tokio::test]
async fn test_memory_scanner_process_scan() {
    let mut scanner = MemoryScanner::new();
    
    // Add a test signature that should match our mock data
    let threat_info = ThreatInfo::new(
        "PE Header Detection".to_string(),
        ThreatType::Suspicious,
        ThreatSeverity::Medium,
        PathBuf::from("memory://pe_header"),
        "b".repeat(64),
        DetectionMethod::Signature,
    ).unwrap();
    
    let signature = MemorySignature {
        id: "pe_header_test".to_string(),
        pattern: vec![0x4D, 0x5A, 0x90, 0x00], // PE header pattern
        mask: vec![0xFF, 0xFF, 0xFF, 0xFF],
        threat_info,
        min_offset: 0,
        max_offset: None,
    };
    
    scanner.add_signature(signature);
    
    // Scan a mock process
    let result = scanner.scan_process_memory(1234).await;
    assert!(result.is_ok());
    
    let scan_result = result.unwrap();
    assert_eq!(scan_result.process_id, 1234);
    assert!(scan_result.scan_duration_ms >= 0); // Allow 0 for fast tests
    assert!(scan_result.scan_stats.regions_scanned > 0);
    assert!(scan_result.scan_stats.bytes_scanned > 0);
}

#[tokio::test]
async fn test_memory_scanner_pattern_matching() {
    let scanner = MemoryScanner::new();
    
    // Test exact pattern match
    let pattern = vec![0xDE, 0xAD, 0xBE, 0xEF];
    let mask = vec![0xFF, 0xFF, 0xFF, 0xFF];
    let data = vec![0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00];
    
    let result = scanner.find_pattern(&data, &pattern, &mask);
    assert_eq!(result, Some(2));
    
    // Test pattern with wildcards
    let pattern = vec![0xDE, 0x00, 0xBE, 0xEF];
    let mask = vec![0xFF, 0x00, 0xFF, 0xFF]; // Second byte is wildcard
    let data = vec![0x00, 0x00, 0xDE, 0xFF, 0xBE, 0xEF, 0x00, 0x00];
    
    let result = scanner.find_pattern(&data, &pattern, &mask);
    assert_eq!(result, Some(2));
    
    // Test no match
    let pattern = vec![0xCA, 0xFE, 0xBA, 0xBE];
    let mask = vec![0xFF, 0xFF, 0xFF, 0xFF];
    let data = vec![0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00];
    
    let result = scanner.find_pattern(&data, &pattern, &mask);
    assert_eq!(result, None);
}

#[tokio::test]
async fn test_memory_scanner_suspicious_region_detection() {
    let scanner = MemoryScanner::new();
    
    // Test executable heap (suspicious)
    let suspicious_region = hadron_core::MemoryRegion {
        base_address: 0x10000000,
        size: 1024,
        protection: hadron_core::MemoryProtection::ExecuteReadWrite,
        region_type: hadron_core::MemoryRegionType::Heap,
        module_name: None,
    };
    
    assert!(scanner.is_suspicious_memory_region(&suspicious_region));
    
    // Test normal executable image (not suspicious)
    let normal_region = hadron_core::MemoryRegion {
        base_address: 0x00400000,
        size: 1024,
        protection: hadron_core::MemoryProtection::ExecuteRead,
        region_type: hadron_core::MemoryRegionType::Image,
        module_name: Some("test.exe".to_string()),
    };
    
    assert!(!scanner.is_suspicious_memory_region(&normal_region));
    
    // Test large executable region without module name (suspicious)
    let large_region = hadron_core::MemoryRegion {
        base_address: 0x20000000,
        size: 20 * 1024 * 1024, // 20MB
        protection: hadron_core::MemoryProtection::ExecuteRead,
        region_type: hadron_core::MemoryRegionType::Private,
        module_name: None,
    };
    
    assert!(scanner.is_suspicious_memory_region(&large_region));
}

#[tokio::test]
async fn test_memory_scanner_scan_result_conversion() {
    let scanner = MemoryScanner::new();
    
    // Create a mock memory scan result
    let memory_result = hadron_core::MemoryScanResult {
        process_id: 1234,
        process_name: "test.exe".to_string(),
        threats_found: vec![],
        rootkit_indicators: vec![],
        scan_stats: hadron_core::MemoryScanStats::default(),
        scan_duration_ms: 1000,
    };
    
    let scan_result = scanner.to_scan_result(memory_result);
    
    assert!(scan_result.scan_id != uuid::Uuid::nil());
    assert_eq!(scan_result.scanned_files, 0);
    assert!(scan_result.threats_found.is_empty());
}

#[tokio::test]
async fn test_memory_scanner_all_processes() {
    let mut scanner = MemoryScanner::new();
    
    let results = scanner.scan_all_processes().await;
    assert!(results.is_ok());
    
    let scan_results = results.unwrap();
    assert!(!scan_results.is_empty()); // Should have scanned some mock processes
    
    // Verify each result has valid data
    for result in scan_results {
        assert!(result.process_id > 0);
        assert!(!result.process_name.is_empty());
        assert!(result.scan_duration_ms >= 0); // Allow 0 for fast tests
        assert!(result.scan_stats.regions_scanned > 0);
    }
}