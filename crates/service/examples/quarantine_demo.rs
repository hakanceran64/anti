use av_service::quarantine::{QuarantineManagerImpl, QuarantineStatistics};
use hadron_core::{QuarantineOperations, ThreatInfo, ThreatType, ThreatSeverity, DetectionMethod};
use hadron_core::config::QuarantineConfig;
use std::path::PathBuf;
use tempfile::TempDir;
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::init();
    println!("🔒 Windows Antivirus Quarantine System Demo");
    println!("============================================");
    let temp_dir = TempDir::new()?;
    let quarantine_path = temp_dir.path().join("quarantine");
    let key_path = temp_dir.path().join("quarantine.key");
    println!("📁 Using temporary directory: {}", temp_dir.path().display());
    let config = QuarantineConfig {
        quarantine_path: quarantine_path.clone(),
        max_quarantine_size_mb: 100,
        auto_delete_after_days: 30,
        encryption_key_path: key_path.clone(),
    };
    println!("⚙️  Configuration:");
    println!("   Quarantine path: {}", quarantine_path.display());
    println!("   Max size: {} MB", config.max_quarantine_size_mb);
    println!("   Auto-delete after: {} days", config.auto_delete_after_days);
    println!("   Encryption key: {}", key_path.display());
    println!("\n🚀 Initializing quarantine manager...");
    let quarantine_manager = QuarantineManagerImpl::new(&config).await?;
    println!("✅ Quarantine manager initialized successfully!");
    println!("\n📄 Creating test malware files...");
    let test_files = vec![
        ("virus.exe", "This is a test virus file", ThreatType::Virus, ThreatSeverity::High),
        ("trojan.dll", "This is a test trojan file", ThreatType::Trojan, ThreatSeverity::Critical),
        ("spyware.bat", "This is a test spyware file", ThreatType::Spyware, ThreatSeverity::Medium),
    ];
    let mut quarantine_ids = Vec::new();
    for (filename, content, threat_type, severity) in test_files {
        let test_file = temp_dir.path().join(filename);
        std::fs::write(&test_file, content)?;
        let threat_info = ThreatInfo::new(
            format!("Test.{:?}", threat_type),
            threat_type.clone(),
            severity.clone(),
            test_file.clone(),
            format!("{:064}", filename.len()),
            DetectionMethod::Signature,
        )?;
        println!("   Created: {} ({:?}, {:?})", filename, threat_type, severity);
        println!("   🔒 Quarantining {}...", filename);
        let quarantine_id = quarantine_manager.quarantine_file(&test_file, &threat_info).await?;
        quarantine_ids.push((quarantine_id, filename.to_string(), test_file));
        if !test_file.exists() {
            println!("   ✅ Original file removed successfully");
        } else {
            println!("   ❌ Original file still exists!");
        }
    }
    println!("\n📋 Listing quarantined files...");
    let quarantined_files = quarantine_manager.list_quarantined().await?;
    println!("   Found {} quarantined files:", quarantined_files.len());
    for entry in &quarantined_files {
        println!("   - ID: {}", entry.id);
        println!("     Original: {}", entry.original_path.display());
        println!("     Threat: {} ({:?})", entry.threat_info.name, entry.threat_info.threat_type);
        println!("     Size: {} bytes", entry.file_size);
        println!("     Quarantined: {}", entry.quarantine_time.format("%Y-%m-%d %H:%M:%S"));
        println!();
    }
    println!("📊 Quarantine statistics:");
    let stats = quarantine_manager.get_statistics().await?;
    println!("   Total entries: {}", stats.total_entries);
    println!("   Total size: {} bytes", stats.total_size_bytes);
    println!("   Threat types:");
    for (threat_type, count) in &stats.threat_type_distribution {
        println!("     {:?}: {}", threat_type, count);
    }
    println!("   Severity distribution:");
    for (severity, count) in &stats.severity_distribution {
        println!("     {:?}: {}", severity, count);
    }
    if let Some((quarantine_id, filename, original_path)) = quarantine_ids.first() {
        println!("\n🔓 Testing restore operation for {}...", filename);
        quarantine_manager.restore_file(*quarantine_id).await?;
        if original_path.exists() {
            println!("   ✅ File restored successfully!");
            let restored_content = std::fs::read_to_string(original_path)?;
            println!("   📄 Restored content: {}", restored_content);
        } else {
            println!("   ❌ File restoration failed!");
        }
    }
    if let Some((quarantine_id, filename, _)) = quarantine_ids.get(1) {
        println!("\n🗑️  Testing delete operation for {}...", filename);
        quarantine_manager.delete_quarantined(*quarantine_id).await?;
        println!("   ✅ File deleted from quarantine successfully!");
    }
    println!("\n📊 Final quarantine statistics:");
    let final_stats = quarantine_manager.get_statistics().await?;
    println!("   Total entries: {}", final_stats.total_entries);
    println!("   Total size: {} bytes", final_stats.total_size_bytes);
    println!("\n🔍 Testing integrity verification...");
    let corrupted_entries = quarantine_manager.verify_integrity().await?;
    if corrupted_entries.is_empty() {
        println!("   ✅ All quarantine entries are intact!");
    } else {
        println!("   ⚠️  Found {} corrupted entries", corrupted_entries.len());
    }
    println!("\n🎉 Quarantine system demo completed successfully!");
    println!("   The quarantine system supports:");
    println!("   ✅ AES-256-GCM encryption");
    println!("   ✅ SQLite metadata database");
    println!("   ✅ File integrity verification");
    println!("   ✅ Restore and delete operations");
    println!("   ✅ Statistics and monitoring");
    Ok(())
}