use hadron_core::{SignatureDatabase, ThreatType, ThreatSeverity, DetectionMethod};
use std::path::PathBuf;
use std::fs;
use tempfile::TempDir;

#[test]
fn test_eicar_detection() {
    let temp_dir = TempDir::new().unwrap();
    
    // Create EICAR test file
    let eicar_file = temp_dir.path().join("eicar.com");
    fs::write(&eicar_file, "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*").unwrap();
    
    // Load signature database
    let signatures_path = PathBuf::from("signatures");
    let db = SignatureDatabase::new(signatures_path);
    
    // Load signatures if directory exists
    if let Ok(entries) = fs::read_dir("signatures") {
        let mut rules_files = Vec::new();
        for entry in entries {
            if let Ok(entry) = entry {
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) == Some("yar") {
                    rules_files.push(path);
                }
            }
        }
        
        if !rules_files.is_empty() {
            let stats = db.load_signatures(&rules_files).unwrap();
            assert!(stats.compiled_rules > 0);
            
            // Scan EICAR file
            let matches = db.scan_file(&eicar_file).unwrap();
            
            // Should detect EICAR
            assert!(!matches.is_empty(), "EICAR file should be detected");
            
            // Convert to threats
            let threats = db.matches_to_threats(matches, &eicar_file).unwrap();
            assert!(!threats.is_empty());
            
            // Verify threat properties
            let threat = &threats[0];
            assert_eq!(threat.detection_method, DetectionMethod::Signature);
            assert_eq!(threat.file_path, eicar_file);
        }
    }
}

#[test]
fn test_clean_file_detection() {
    let temp_dir = TempDir::new().unwrap();
    
    // Create clean test file
    let clean_file = temp_dir.path().join("clean.txt");
    fs::write(&clean_file, "This is a clean file with no malware signatures.").unwrap();
    
    // Load signature database
    let signatures_path = PathBuf::from("signatures");
    let db = SignatureDatabase::new(signatures_path);
    
    // Load signatures if directory exists
    if let Ok(entries) = fs::read_dir("signatures") {
        let mut rules_files = Vec::new();
        for entry in entries {
            if let Ok(entry) = entry {
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) == Some("yar") {
                    rules_files.push(path);
                }
            }
        }
        
        if !rules_files.is_empty() {
            db.load_signatures(&rules_files).unwrap();
            
            // Scan clean file
            let matches = db.scan_file(&clean_file).unwrap();
            
            // Should not detect anything
            assert!(matches.is_empty(), "Clean file should not trigger any detections");
        }
    }
}

#[test]
fn test_signature_database_statistics() {
    let signatures_path = PathBuf::from("signatures");
    let db = SignatureDatabase::new(signatures_path);
    
    // Load signatures if directory exists
    if let Ok(entries) = fs::read_dir("signatures") {
        let mut rules_files = Vec::new();
        for entry in entries {
            if let Ok(entry) = entry {
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) == Some("yar") {
                    rules_files.push(path);
                }
            }
        }
        
        if !rules_files.is_empty() {
            let compilation_stats = db.load_signatures(&rules_files).unwrap();
            let db_stats = db.get_statistics();
            
            // Verify compilation statistics
            assert!(compilation_stats.total_rules > 0);
            assert_eq!(compilation_stats.compiled_rules, compilation_stats.total_rules - compilation_stats.failed_rules);
            assert!(compilation_stats.compilation_time_ms > 0);
            
            // Verify database statistics
            assert_eq!(db_stats.total_signatures, compilation_stats.compiled_rules);
            assert!(db_stats.last_update.is_some());
            assert!(db_stats.memory_usage_bytes > 0);
            
            // Check threat type distribution
            let mut total_by_type = 0;
            for count in db_stats.threat_type_distribution.values() {
                total_by_type += count;
            }
            assert_eq!(total_by_type, db_stats.total_signatures);
            
            // Check severity distribution
            let mut total_by_severity = 0;
            for count in db_stats.severity_distribution.values() {
                total_by_severity += count;
            }
            assert_eq!(total_by_severity, db_stats.total_signatures);
        }
    }
}

#[test]
fn test_malware_pattern_detection() {
    let temp_dir = TempDir::new().unwrap();
    
    // Create file with suspicious patterns
    let suspicious_file = temp_dir.path().join("suspicious.exe");
    let suspicious_content = b"This file contains cmd.exe /c and powershell.exe with socket connect send recv backdoor functionality";
    fs::write(&suspicious_file, suspicious_content).unwrap();
    
    // Load signature database
    let signatures_path = PathBuf::from("signatures");
    let db = SignatureDatabase::new(signatures_path);
    
    // Load signatures if directory exists
    if let Ok(entries) = fs::read_dir("signatures") {
        let mut rules_files = Vec::new();
        for entry in entries {
            if let Ok(entry) = entry {
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) == Some("yar") {
                    rules_files.push(path);
                }
            }
        }
        
        if !rules_files.is_empty() {
            db.load_signatures(&rules_files).unwrap();
            
            // Scan suspicious file
            let matches = db.scan_file(&suspicious_file).unwrap();
            
            if !matches.is_empty() {
                // Convert to threats
                let threats = db.matches_to_threats(matches, &suspicious_file).unwrap();
                
                // Verify detection
                assert!(!threats.is_empty());
                
                // Check that it's detected as trojan (based on our rules)
                let trojan_threats: Vec<_> = threats.iter()
                    .filter(|t| t.threat_type == ThreatType::Trojan)
                    .collect();
                
                if !trojan_threats.is_empty() {
                    assert_eq!(trojan_threats[0].detection_method, DetectionMethod::Signature);
                }
            }
        }
    }
}

#[test]
fn test_concurrent_scanning() {
    use std::sync::Arc;
    use std::thread;
    
    let temp_dir = TempDir::new().unwrap();
    
    // Create multiple test files
    let mut test_files = Vec::new();
    for i in 0..10 {
        let file_path = temp_dir.path().join(format!("test_{}.txt", i));
        let content = if i % 3 == 0 {
            // Every third file contains EICAR
            "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        } else {
            "Clean file content"
        };
        fs::write(&file_path, content).unwrap();
        test_files.push(file_path);
    }
    
    // Load signature database
    let signatures_path = PathBuf::from("signatures");
    let db = Arc::new(SignatureDatabase::new(signatures_path));
    
    // Load signatures if directory exists
    if let Ok(entries) = fs::read_dir("signatures") {
        let mut rules_files = Vec::new();
        for entry in entries {
            if let Ok(entry) = entry {
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) == Some("yar") {
                    rules_files.push(path);
                }
            }
        }
        
        if !rules_files.is_empty() {
            db.load_signatures(&rules_files).unwrap();
            
            // Scan files concurrently
            let handles: Vec<_> = test_files.into_iter().map(|file_path| {
                let db_clone = Arc::clone(&db);
                thread::spawn(move || {
                    db_clone.scan_file(&file_path)
                })
            }).collect();
            
            // Collect results
            let mut total_matches = 0;
            for handle in handles {
                let matches = handle.join().unwrap().unwrap();
                total_matches += matches.len();
            }
            
            // Should have detected some threats (EICAR files)
            assert!(total_matches > 0, "Should detect EICAR in some files");
        }
    }
}

#[test]
fn test_memory_scanning() {
    // Load signature database
    let signatures_path = PathBuf::from("signatures");
    let db = SignatureDatabase::new(signatures_path);
    
    // Load signatures if directory exists
    if let Ok(entries) = fs::read_dir("signatures") {
        let mut rules_files = Vec::new();
        for entry in entries {
            if let Ok(entry) = entry {
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) == Some("yar") {
                    rules_files.push(path);
                }
            }
        }
        
        if !rules_files.is_empty() {
            db.load_signatures(&rules_files).unwrap();
            
            // Test data with EICAR signature
            let eicar_data = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
            let matches = db.scan_data(eicar_data).unwrap();
            
            // Should detect EICAR
            assert!(!matches.is_empty(), "Should detect EICAR in memory");
            
            // Test clean data
            let clean_data = b"This is clean data with no malware signatures";
            let clean_matches = db.scan_data(clean_data).unwrap();
            
            // Should not detect anything
            assert!(clean_matches.is_empty(), "Should not detect anything in clean data");
        }
    }
}