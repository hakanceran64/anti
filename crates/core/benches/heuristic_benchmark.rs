use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use hadron_core::{HeuristicAnalyzer, FileInfo, AdvancedPEAnalyzer};
use tempfile::TempDir;
use tokio::fs;
use std::path::PathBuf;

fn create_test_executable(dir: &std::path::Path, name: &str, content: &[u8]) -> PathBuf {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let file_path = dir.join(name);
    
    let mut pe_content = vec![0u8; 64];
    pe_content[0] = 0x4D; // M
    pe_content[1] = 0x5A; // Z
    pe_content[60] = 60;
    pe_content.extend_from_slice(&[0x50, 0x45, 0x00, 0x00]); // PE signature
    pe_content.extend_from_slice(content);
    
    rt.block_on(fs::write(&file_path, pe_content)).unwrap();
    file_path
}

fn create_file_info(path: PathBuf, size: u64, is_executable: bool) -> FileInfo {
    FileInfo {
        path,
        size,
        modified: std::time::SystemTime::now(),
        created: std::time::SystemTime::now(),
        is_executable,
        extension: Some("exe".to_string()),
        mime_type: Some("application/x-msdownload".to_string()),
    }
}

fn benchmark_heuristic_analysis(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let temp_dir = TempDir::new().unwrap();
    
    let mut group = c.benchmark_group("heuristic_analysis");
    
    // Test different types of content
    let test_cases = vec![
        ("clean", b"This is a clean executable with normal functionality"),
        ("suspicious", b"CreateRemoteThread WriteProcessMemory VirtualAllocEx keylog password"),
        ("ransomware", b"CryptEncrypt CryptGenKey bitcoin ransom decrypt your files"),
        ("keylogger", b"GetAsyncKeyState SetWindowsHookEx keylog capture keystrokes"),
    ];
    
    for (case_name, content) in test_cases {
        group.bench_with_input(
            BenchmarkId::new("analyze_file", case_name),
            &(case_name, content),
            |b, &(name, content)| {
                let test_file = create_test_executable(temp_dir.path(), &format!("{}.exe", name), content);
                let file_info = create_file_info(test_file.clone(), content.len() as u64 + 68, true);
                let analyzer = HeuristicAnalyzer::new();
                
                b.to_async(&rt).iter(|| async {
                    black_box(analyzer.analyze_file(&test_file, &file_info).await.unwrap());
                });
            },
        );
    }
    
    group.finish();
}

fn benchmark_entropy_calculation(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let temp_dir = TempDir::new().unwrap();
    
    let mut group = c.benchmark_group("entropy_calculation");
    
    for file_size in [1024, 10240, 102400, 1048576].iter() { // 1KB to 1MB
        group.bench_with_input(
            BenchmarkId::new("calculate_entropy", file_size),
            file_size,
            |b, &size| {
                // Create file with mixed entropy
                let mut content = Vec::new();
                for i in 0..(size / 256) {
                    content.extend_from_slice(&(0..=255).collect::<Vec<u8>>());
                }
                content.resize(size, 0);
                
                let test_file = temp_dir.path().join(format!("entropy_test_{}.bin", size));
                rt.block_on(fs::write(&test_file, content)).unwrap();
                
                let analyzer = HeuristicAnalyzer::new();
                
                b.to_async(&rt).iter(|| async {
                    // This would call the entropy analyzer internally
                    let file_info = create_file_info(test_file.clone(), size as u64, false);
                    black_box(analyzer.analyze_file(&test_file, &file_info).await.unwrap());
                });
            },
        );
    }
    
    group.finish();
}

fn benchmark_string_analysis(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let temp_dir = TempDir::new().unwrap();
    
    let mut group = c.benchmark_group("string_analysis");
    
    for string_count in [10, 50, 100, 500].iter() {
        group.bench_with_input(
            BenchmarkId::new("analyze_strings", string_count),
            string_count,
            |b, &count| {
                // Create content with many suspicious strings
                let mut content = Vec::new();
                let suspicious_strings = [
                    "cmd.exe", "powershell.exe", "keylog", "password", "backdoor",
                    "CryptEncrypt", "bitcoin", "ransom", "CreateRemoteThread",
                    "WriteProcessMemory", "VirtualAllocEx", "SetWindowsHookEx"
                ];
                
                for i in 0..count {
                    let string = suspicious_strings[i % suspicious_strings.len()];
                    content.extend_from_slice(string.as_bytes());
                    content.push(b' ');
                    content.extend_from_slice(b"normal content ");
                }
                
                let test_file = create_test_executable(temp_dir.path(), &format!("strings_{}.exe", count), &content);
                let file_info = create_file_info(test_file.clone(), content.len() as u64 + 68, true);
                let analyzer = HeuristicAnalyzer::new();
                
                b.to_async(&rt).iter(|| async {
                    black_box(analyzer.analyze_file(&test_file, &file_info).await.unwrap());
                });
            },
        );
    }
    
    group.finish();
}

fn benchmark_pe_analysis(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let temp_dir = TempDir::new().unwrap();
    
    let mut group = c.benchmark_group("pe_analysis");
    
    for file_size in [1024, 10240, 102400].iter() {
        group.bench_with_input(
            BenchmarkId::new("analyze_pe", file_size),
            file_size,
            |b, &size| {
                let content = vec![0u8; size - 68]; // Subtract PE header size
                let test_file = create_test_executable(temp_dir.path(), &format!("pe_test_{}.exe", size), &content);
                let analyzer = AdvancedPEAnalyzer::new();
                
                b.to_async(&rt).iter(|| async {
                    black_box(analyzer.analyze_pe_file(&test_file).await.unwrap());
                });
            },
        );
    }
    
    group.finish();
}

fn benchmark_rule_evaluation(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let temp_dir = TempDir::new().unwrap();
    
    let mut group = c.benchmark_group("rule_evaluation");
    
    for rule_count in [5, 10, 20].iter() {
        group.bench_with_input(
            BenchmarkId::new("evaluate_rules", rule_count),
            rule_count,
            |b, &count| {
                // Create content that will trigger multiple rules
                let content = b"CreateRemoteThread WriteProcessMemory VirtualAllocEx GetAsyncKeyState SetWindowsHookEx keylog password backdoor CryptEncrypt bitcoin ransom decrypt";
                let test_file = create_test_executable(temp_dir.path(), &format!("rules_{}.exe", count), content);
                let file_info = create_file_info(test_file.clone(), content.len() as u64 + 68, true);
                
                let mut analyzer = HeuristicAnalyzer::new();
                
                // Add more rules to test scalability
                for i in 0..(count - analyzer.get_rules().len()) {
                    let rule = hadron_core::HeuristicRule {
                        id: format!("BENCH_{:03}", i),
                        name: format!("Benchmark Rule {}", i),
                        description: "Benchmark rule for testing".to_string(),
                        severity: hadron_core::ThreatSeverity::Medium,
                        threat_type: hadron_core::ThreatType::Suspicious,
                        conditions: vec![
                            hadron_core::HeuristicCondition::FileExtension { 
                                extensions: vec!["exe".to_string()] 
                            }
                        ],
                        weight: 0.5,
                        enabled: true,
                    };
                    analyzer.add_rule(rule);
                }
                
                b.to_async(&rt).iter(|| async {
                    black_box(analyzer.analyze_file(&test_file, &file_info).await.unwrap());
                });
            },
        );
    }
    
    group.finish();
}

fn benchmark_threat_conversion(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let temp_dir = TempDir::new().unwrap();
    
    let mut group = c.benchmark_group("threat_conversion");
    
    for threat_count in [1, 5, 10, 20].iter() {
        group.bench_with_input(
            BenchmarkId::new("convert_threats", threat_count),
            threat_count,
            |b, &count| {
                // Create content that will generate multiple threats
                let mut content = Vec::new();
                let patterns = [
                    b"CreateRemoteThread WriteProcessMemory VirtualAllocEx",
                    b"GetAsyncKeyState SetWindowsHookEx keylog",
                    b"CryptEncrypt bitcoin ransom decrypt",
                    b"RegSetValue RegCreateKey HKEY_CURRENT_USER",
                ];
                
                for i in 0..count {
                    content.extend_from_slice(patterns[i % patterns.len()]);
                    content.push(b' ');
                }
                
                let test_file = create_test_executable(temp_dir.path(), &format!("threats_{}.exe", count), &content);
                let file_info = create_file_info(test_file.clone(), content.len() as u64 + 68, true);
                let analyzer = HeuristicAnalyzer::new();
                
                b.to_async(&rt).iter(|| async {
                    let result = analyzer.analyze_file(&test_file, &file_info).await.unwrap();
                    black_box(analyzer.results_to_threats(&result, &test_file, "abcd1234").unwrap());
                });
            },
        );
    }
    
    group.finish();
}

fn benchmark_concurrent_analysis(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let temp_dir = TempDir::new().unwrap();
    
    let mut group = c.benchmark_group("concurrent_analysis");
    
    // Create test files
    let test_files: Vec<_> = (0..10).map(|i| {
        let content = format!("CreateRemoteThread WriteProcessMemory test file {}", i);
        create_test_executable(temp_dir.path(), &format!("concurrent_{}.exe", i), content.as_bytes())
    }).collect();
    
    for thread_count in [1, 2, 4].iter() {
        group.bench_with_input(
            BenchmarkId::new("concurrent_threads", thread_count),
            thread_count,
            |b, &threads| {
                b.to_async(&rt).iter(|| async {
                    let analyzer = std::sync::Arc::new(HeuristicAnalyzer::new());
                    let mut handles = Vec::new();
                    let files_per_thread = test_files.len() / threads;
                    
                    for i in 0..threads {
                        let start_idx = i * files_per_thread;
                        let end_idx = if i == threads - 1 { 
                            test_files.len() 
                        } else { 
                            (i + 1) * files_per_thread 
                        };
                        
                        let analyzer_clone = std::sync::Arc::clone(&analyzer);
                        let files_slice = test_files[start_idx..end_idx].to_vec();
                        
                        let handle = tokio::spawn(async move {
                            for file_path in files_slice {
                                let file_info = create_file_info(file_path.clone(), 1000, true);
                                analyzer_clone.analyze_file(&file_path, &file_info).await.unwrap();
                            }
                        });
                        
                        handles.push(handle);
                    }
                    
                    for handle in handles {
                        handle.await.unwrap();
                    }
                    
                    black_box(());
                });
            },
        );
    }
    
    group.finish();
}

criterion_group!(
    benches,
    benchmark_heuristic_analysis,
    benchmark_entropy_calculation,
    benchmark_string_analysis,
    benchmark_pe_analysis,
    benchmark_rule_evaluation,
    benchmark_threat_conversion,
    benchmark_concurrent_analysis
);
criterion_main!(benches);