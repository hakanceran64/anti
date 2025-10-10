use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use hadron_service::ScanEngineImpl;
use hadron_core::ScanType;
use tempfile::TempDir;
use tokio::fs;
use std::path::PathBuf;

fn create_test_files(dir: &std::path::Path, count: usize, size: usize) -> Vec<PathBuf> {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut files = Vec::new();
    
    for i in 0..count {
        let file_path = dir.join(format!("test_{}.txt", i));
        let content = vec![b'A'; size];
        rt.block_on(fs::write(&file_path, content)).unwrap();
        files.push(file_path);
    }
    
    files
}

fn create_test_executables(dir: &std::path::Path, count: usize) -> Vec<PathBuf> {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut files = Vec::new();
    
    for i in 0..count {
        let file_path = dir.join(format!("test_{}.exe", i));
        
        // Create fake PE file
        let mut pe_content = vec![0u8; 64];
        pe_content[0] = 0x4D; // M
        pe_content[1] = 0x5A; // Z
        pe_content[60] = 60;
        pe_content.extend_from_slice(&[0x50, 0x45, 0x00, 0x00]); // PE signature
        pe_content.extend_from_slice(format!("Test executable content {}", i).as_bytes());
        
        rt.block_on(fs::write(&file_path, pe_content)).unwrap();
        files.push(file_path);
    }
    
    files
}

fn benchmark_single_file_scan(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let temp_dir = TempDir::new().unwrap();
    
    let mut group = c.benchmark_group("single_file_scan");
    
    for file_size in [1024, 10240, 102400].iter() { // 1KB, 10KB, 100KB
        group.bench_with_input(
            BenchmarkId::new("text_file", file_size),
            file_size,
            |b, &size| {
                let test_file = temp_dir.path().join("benchmark.txt");
                let content = vec![b'A'; size];
                rt.block_on(fs::write(&test_file, content)).unwrap();
                
                let engine = ScanEngineImpl::new().unwrap();
                rt.block_on(engine.start()).unwrap();
                
                b.to_async(&rt).iter(|| async {
                    black_box(engine.scan_file(&test_file).await.unwrap());
                });
            },
        );
    }
    
    group.finish();
}

fn benchmark_executable_scan(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let temp_dir = TempDir::new().unwrap();
    
    let mut group = c.benchmark_group("executable_scan");
    
    for exe_count in [1, 5, 10].iter() {
        group.bench_with_input(
            BenchmarkId::new("pe_files", exe_count),
            exe_count,
            |b, &count| {
                let exe_files = create_test_executables(temp_dir.path(), count);
                let engine = ScanEngineImpl::new().unwrap();
                rt.block_on(engine.start()).unwrap();
                
                b.to_async(&rt).iter(|| async {
                    for exe_file in &exe_files {
                        black_box(engine.scan_file(exe_file).await.unwrap());
                    }
                });
            },
        );
    }
    
    group.finish();
}

fn benchmark_directory_scan(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let temp_dir = TempDir::new().unwrap();
    
    let mut group = c.benchmark_group("directory_scan");
    
    for file_count in [10, 50, 100].iter() {
        group.bench_with_input(
            BenchmarkId::new("files", file_count),
            file_count,
            |b, &count| {
                let _test_files = create_test_files(temp_dir.path(), count, 1024);
                let engine = ScanEngineImpl::new().unwrap();
                rt.block_on(engine.start()).unwrap();
                
                b.to_async(&rt).iter(|| async {
                    let targets = vec![temp_dir.path().to_path_buf()];
                    let job_id = engine.start_scan(ScanType::Custom(targets), vec![]).await.unwrap();
                    
                    // Wait for completion
                    loop {
                        let status = engine.get_scan_status(job_id).await.unwrap();
                        if !matches!(status, hadron_core::ScanStatus::Running) {
                            break;
                        }
                        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
                    }
                    
                    black_box(job_id);
                });
            },
        );
    }
    
    group.finish();
}

fn benchmark_hash_calculation(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let temp_dir = TempDir::new().unwrap();
    
    let mut group = c.benchmark_group("hash_calculation");
    
    for file_size in [1024, 10240, 102400, 1048576].iter() { // 1KB to 1MB
        group.bench_with_input(
            BenchmarkId::new("sha256", file_size),
            file_size,
            |b, &size| {
                let test_file = temp_dir.path().join("hash_test.bin");
                let content = vec![0u8; size];
                rt.block_on(fs::write(&test_file, content)).unwrap();
                
                let engine = ScanEngineImpl::new().unwrap();
                let file_scanner = engine.get_file_scanner();
                
                b.to_async(&rt).iter(|| async {
                    black_box(file_scanner.calculate_sha256(&test_file).await.unwrap());
                });
            },
        );
    }
    
    group.finish();
}

fn benchmark_file_info_collection(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let temp_dir = TempDir::new().unwrap();
    
    let mut group = c.benchmark_group("file_info");
    
    for file_count in [10, 50, 100].iter() {
        group.bench_with_input(
            BenchmarkId::new("get_info", file_count),
            file_count,
            |b, &count| {
                let test_files = create_test_files(temp_dir.path(), count, 1024);
                let engine = ScanEngineImpl::new().unwrap();
                let file_scanner = engine.get_file_scanner();
                
                b.to_async(&rt).iter(|| async {
                    for file_path in &test_files {
                        black_box(file_scanner.get_file_info(file_path).await.unwrap());
                    }
                });
            },
        );
    }
    
    group.finish();
}

fn benchmark_directory_walking(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let temp_dir = TempDir::new().unwrap();
    
    let mut group = c.benchmark_group("directory_walking");
    
    // Create nested directory structure
    rt.block_on(async {
        for i in 0..5 {
            let sub_dir = temp_dir.path().join(format!("subdir_{}", i));
            fs::create_dir(&sub_dir).await.unwrap();
            
            for j in 0..10 {
                let file_path = sub_dir.join(format!("file_{}_{}.txt", i, j));
                fs::write(&file_path, format!("Content {} {}", i, j)).await.unwrap();
            }
        }
    });
    
    group.bench_function("walk_directory", |b| {
        let engine = ScanEngineImpl::new().unwrap();
        let directory_walker = engine.get_directory_walker();
        
        b.to_async(&rt).iter(|| async {
            black_box(directory_walker.walk_directory(temp_dir.path()).await.unwrap());
        });
    });
    
    group.finish();
}

fn benchmark_string_extraction(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let temp_dir = TempDir::new().unwrap();
    
    let mut group = c.benchmark_group("string_extraction");
    
    for file_size in [1024, 10240, 102400].iter() {
        group.bench_with_input(
            BenchmarkId::new("extract_strings", file_size),
            file_size,
            |b, &size| {
                let test_file = temp_dir.path().join("strings_test.bin");
                
                // Create file with mixed binary and string content
                let mut content = Vec::new();
                for i in 0..(size / 20) {
                    content.extend_from_slice(b"test string ");
                    content.push(i as u8);
                    content.extend_from_slice(&[0xFF, 0xFE, 0x00]);
                }
                content.resize(size, 0);
                
                rt.block_on(fs::write(&test_file, content)).unwrap();
                
                let engine = ScanEngineImpl::new().unwrap();
                let file_scanner = engine.get_file_scanner();
                
                b.to_async(&rt).iter(|| async {
                    black_box(file_scanner.extract_strings(&test_file, 4).await.unwrap());
                });
            },
        );
    }
    
    group.finish();
}

fn benchmark_concurrent_scanning(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let temp_dir = TempDir::new().unwrap();
    
    let mut group = c.benchmark_group("concurrent_scanning");
    
    // Create test files
    let test_files = create_test_files(temp_dir.path(), 20, 1024);
    
    for thread_count in [1, 2, 4].iter() {
        group.bench_with_input(
            BenchmarkId::new("threads", thread_count),
            thread_count,
            |b, &threads| {
                b.to_async(&rt).iter(|| async {
                    let engine = std::sync::Arc::new(ScanEngineImpl::new().unwrap());
                    engine.start().await.unwrap();
                    
                    let mut handles = Vec::new();
                    let files_per_thread = test_files.len() / threads;
                    
                    for i in 0..threads {
                        let start_idx = i * files_per_thread;
                        let end_idx = if i == threads - 1 { 
                            test_files.len() 
                        } else { 
                            (i + 1) * files_per_thread 
                        };
                        
                        let engine_clone = std::sync::Arc::clone(&engine);
                        let files_slice = test_files[start_idx..end_idx].to_vec();
                        
                        let handle = tokio::spawn(async move {
                            for file_path in files_slice {
                                engine_clone.scan_file(&file_path).await.unwrap();
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
    benchmark_single_file_scan,
    benchmark_executable_scan,
    benchmark_directory_scan,
    benchmark_hash_calculation,
    benchmark_file_info_collection,
    benchmark_directory_walking,
    benchmark_string_extraction,
    benchmark_concurrent_scanning
);
criterion_main!(benches);