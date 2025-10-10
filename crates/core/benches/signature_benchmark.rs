use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use hadron_core::{SignatureDatabase, SignatureMetadata, ThreatType, ThreatSeverity};
use tempfile::TempDir;
use std::fs;
fn create_benchmark_yara_rules(rule_count: usize) -> String {
    let mut rules = String::new();
    for i in 0..rule_count {
        rules.push_str(&format!(
            r#"
rule BenchmarkRule{}
{{
    meta:
        description = "Benchmark rule {}"
        author = "Benchmark"
        version = "1.0"
        threat_type = "virus"
        severity = "medium"
    strings:
        $string{} = "BENCHMARK_PATTERN_{}"
        $hex{} = {{ 4D 5A {} 00 }}
    condition:
        $string{} or $hex{}
}}
"#,
            i, i, i, i, i, i % 256, i, i
        ));
    }
    rules
}
fn create_test_data(size: usize, pattern_density: f32) -> Vec<u8> {
    let mut data = vec![0u8; size];
    let pattern = b"BENCHMARK_PATTERN_";
    let pattern_count = (size as f32 * pattern_density) as usize / pattern.len();
    for i in 0..pattern_count {
        let pos = (i * size / pattern_count).min(size - pattern.len());
        data[pos..pos + pattern.len()].copy_from_slice(pattern);
    }
    data
}
fn benchmark_signature_loading(c: &mut Criterion) {
    let mut group = c.benchmark_group("signature_loading");
    for rule_count in [10, 50, 100, 500].iter() {
        group.bench_with_input(
            BenchmarkId::new("load_rules", rule_count),
            rule_count,
            |b, &rule_count| {
                b.iter_with_setup(
                    || {
                        let temp_dir = TempDir::new().unwrap();
                        let rules_file = temp_dir.path().join("benchmark.yar");
                        fs::write(&rules_file, create_benchmark_yara_rules(rule_count)).unwrap();
                        (SignatureDatabase::new(rules_file.clone()), vec![rules_file])
                    },
                    |(db, rules_files)| {
                        black_box(db.load_signatures(&rules_files).unwrap());
                    },
                );
            },
        );
    }
    group.finish();
}
fn benchmark_data_scanning(c: &mut Criterion) {
    let mut group = c.benchmark_group("data_scanning");
    let temp_dir = TempDir::new().unwrap();
    let rules_file = temp_dir.path().join("benchmark.yar");
    fs::write(&rules_file, create_benchmark_yara_rules(100)).unwrap();
    let db = SignatureDatabase::new(rules_file.clone());
    db.load_signatures(&[rules_file]).unwrap();
    for data_size in [1024, 10240, 102400, 1048576].iter() {
        for pattern_density in [0.0, 0.01, 0.1].iter() {
            group.bench_with_input(
                BenchmarkId::new(
                    format!("scan_data_{}KB_{}%", data_size / 1024, (pattern_density * 100.0) as u32),
                    data_size
                ),
                &(*data_size, *pattern_density),
                |b, &(size, density)| {
                    let test_data = create_test_data(size, density);
                    b.iter(|| {
                        black_box(db.scan_data(&test_data).unwrap());
                    });
                },
            );
        }
    }
    group.finish();
}
fn benchmark_file_scanning(c: &mut Criterion) {
    let mut group = c.benchmark_group("file_scanning");
    let temp_dir = TempDir::new().unwrap();
    let rules_file = temp_dir.path().join("benchmark.yar");
    fs::write(&rules_file, create_benchmark_yara_rules(100)).unwrap();
    let db = SignatureDatabase::new(rules_file.clone());
    db.load_signatures(&[rules_file]).unwrap();
    for file_size in [1024, 10240, 102400].iter() {
        group.bench_with_input(
            BenchmarkId::new("scan_file", file_size),
            file_size,
            |b, &size| {
                b.iter_with_setup(
                    || {
                        let test_file = temp_dir.path().join(format!("test_{}.bin", size));
                        let test_data = create_test_data(size, 0.01);
                        fs::write(&test_file, test_data).unwrap();
                        test_file
                    },
                    |test_file| {
                        black_box(db.scan_file(&test_file).unwrap());
                    },
                );
            },
        );
    }
    group.finish();
}
fn benchmark_hash_calculation(c: &mut Criterion) {
    let mut group = c.benchmark_group("hash_calculation");
    let temp_dir = TempDir::new().unwrap();
    for file_size in [1024, 10240, 102400, 1048576].iter() {
        group.bench_with_input(
            BenchmarkId::new("sha256_hash", file_size),
            file_size,
            |b, &size| {
                b.iter_with_setup(
                    || {
                        let test_file = temp_dir.path().join(format!("hash_test_{}.bin", size));
                        let test_data = vec![0u8; size];
                        fs::write(&test_file, test_data).unwrap();
                        test_file
                    },
                    |test_file| {
                        use sha2::{Sha256, Digest};
                        let data = fs::read(&test_file).unwrap();
                        let mut hasher = Sha256::new();
                        hasher.update(&data);
                        let hash = hasher.finalize();
                        black_box(format!("{:x}", hash));
                    },
                );
            },
        );
    }
    group.finish();
}
fn benchmark_concurrent_scanning(c: &mut Criterion) {
    let mut group = c.benchmark_group("concurrent_scanning");
    let temp_dir = TempDir::new().unwrap();
    let rules_file = temp_dir.path().join("benchmark.yar");
    fs::write(&rules_file, create_benchmark_yara_rules(50)).unwrap();
    let db = std::sync::Arc::new(SignatureDatabase::new(rules_file.clone()));
    db.load_signatures(&[rules_file]).unwrap();
    for thread_count in [1, 2, 4, 8].iter() {
        group.bench_with_input(
            BenchmarkId::new("concurrent_scan", thread_count),
            thread_count,
            |b, &threads| {
                let test_data = create_test_data(10240, 0.01);
                b.iter(|| {
                    let handles: Vec<_> = (0..threads)
                        .map(|_| {
                            let db_clone = std::sync::Arc::clone(&db);
                            let data_clone = test_data.clone();
                            std::thread::spawn(move || {
                                db_clone.scan_data(&data_clone).unwrap()
                            })
                        })
                        .collect();
                    for handle in handles {
                        black_box(handle.join().unwrap());
                    }
                });
            },
        );
    }
    group.finish();
}
criterion_group!(
    benches,
    benchmark_signature_loading,
    benchmark_data_scanning,
    benchmark_file_scanning,
    benchmark_hash_calculation,
    benchmark_concurrent_scanning
);
criterion_main!(benches);