use hadron_core::{
    EventLogger, StructuredEvent, EventSeverity, LoggingConfig, AuditEvent, AuditEventType, AuditResult,
    log_structured_security_event, SecurityEventSeverity
};
use std::path::PathBuf;
use chrono::Utc;
use serde_json;
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = LoggingConfig {
        log_level: "info".to_string(),
        log_file_path: PathBuf::from("./demo_event.log"),
        max_log_file_size_mb: 10,
        max_log_files: 5,
        enable_console_logging: true,
        enable_windows_event_log: false,
        enable_json_logging: true,
    };
    let event_logger = EventLogger::new(config)?;
    event_logger.initialize()?;
    println!("EventLogger Demo - Comprehensive Logging System");
    println!("===============================================");
    println!("\n1. Logging basic structured event...");
    let basic_event = StructuredEvent::new(
        "demo_startup",
        EventSeverity::Medium,
        "demo_app",
        "EventLogger demonstration started",
    )
    .with_user("demo_user")
    .with_correlation_id("demo-session-001");
    event_logger.log_structured_event(basic_event)?;
    println!("2. Logging security event with details...");
    let security_details = serde_json::json!({
        "source_ip": "192.168.1.100",
        "user_agent": "DemoClient/1.0",
        "authentication_method": "password",
        "session_duration": 3600
    });
    log_structured_security_event(
        &event_logger,
        "user_authentication",
        EventSeverity::Medium,
        "User successfully authenticated to the system",
        Some("admin"),
        Some(security_details),
    )?;
    println!("3. Logging threat detection event...");
    let threat_details = serde_json::json!({
        "threat_name": "Trojan.Win32.Demo",
        "file_path": "C:\\temp\\suspicious.exe",
        "file_hash": "abc123def456",
        "detection_method": "signature",
        "quarantine_status": "quarantined"
    });
    let threat_event = StructuredEvent::new(
        "threat_detected",
        EventSeverity::Critical,
        "threat_detector",
        "Critical threat detected and quarantined",
    )
    .with_user("system")
    .with_details(threat_details)
    .with_correlation_id("threat-alert-001")
    .with_session_id("scan-session-123");
    event_logger.log_structured_event(threat_event)?;
    println!("4. Logging audit event...");
    let audit_event = AuditEvent {
        event_type: AuditEventType::Configuration,
        user: "admin".to_string(),
        timestamp: Utc::now(),
        resource: "scan_settings".to_string(),
        action: "modify".to_string(),
        result: AuditResult::Success,
        details: Some(serde_json::json!({
            "setting": "real_time_protection",
            "old_value": false,
            "new_value": true
        })),
    };
    event_logger.log_audit_event(audit_event)?;
    println!("5. Logging performance metrics...");
    let performance_metrics = serde_json::json!({
        "cpu_usage_percent": 15.5,
        "memory_usage_mb": 256,
        "disk_io_rate": 1024,
        "network_throughput": 512,
        "scan_rate_files_per_second": 100,
        "active_threads": 4,
        "queue_size": 25
    });
    let performance_event = StructuredEvent::new(
        "performance_metrics",
        EventSeverity::Debug,
        "performance_monitor",
        "System performance metrics collected",
    )
    .with_details(performance_metrics)
    .with_correlation_id("perf-monitor-001");
    event_logger.log_structured_event(performance_event)?;
    println!("6. Logging multiple scan events...");
    for i in 1..=5 {
        let scan_details = serde_json::json!({
            "scan_id": format!("scan-{:03}", i),
            "files_scanned": i * 100,
            "duration_ms": i * 1000,
            "threats_found": if i % 2 == 0 { 1 } else { 0 }
        });
        let scan_event = StructuredEvent::new(
            "scan_completed",
            if i % 2 == 0 { EventSeverity::High } else { EventSeverity::Medium },
            "scan_engine",
            &format!("Scan {} completed", i),
        )
        .with_details(scan_details)
        .with_correlation_id(&format!("scan-batch-{}", i));
        event_logger.log_structured_event(scan_event)?;
    }
    println!("\n7. Event Statistics:");
    let stats = event_logger.get_event_statistics();
    for (event_type, count) in stats {
        println!("   {}: {} events", event_type, count);
    }
    println!("\n8. Testing log rotation and archiving...");
    event_logger.archive_logs()?;
    println!("   Logs archived successfully");
    event_logger.cleanup_old_logs(30)?;
    println!("   Old logs cleaned up (keeping last 30 days)");
    println!("9. Logging complex nested event data...");
    let complex_data = serde_json::json!({
        "scan_summary": {
            "total_files": 10000,
            "scanned_files": 9950,
            "skipped_files": 50,
            "scan_duration": {
                "total_ms": 45000,
                "avg_file_ms": 4.5,
                "max_file_ms": 500
            },
            "threats": {
                "total_found": 3,
                "by_type": {
                    "virus": 1,
                    "trojan": 1,
                    "adware": 1
                },
                "by_severity": {
                    "critical": 1,
                    "high": 1,
                    "medium": 1
                }
            },
            "actions_taken": {
                "quarantined": 2,
                "cleaned": 1,
                "deleted": 0
            }
        },
        "system_state": {
            "cpu_usage": 25.0,
            "memory_usage": 512,
            "disk_space_free": 1024000,
            "network_active": true
        }
    });
    let complex_event = StructuredEvent::new(
        "comprehensive_scan_report",
        EventSeverity::High,
        "scan_engine",
        "Comprehensive system scan completed with detailed analysis",
    )
    .with_user("system")
    .with_details(complex_data)
    .with_correlation_id("comprehensive-scan-001")
    .with_session_id("daily-scan-session");
    event_logger.log_structured_event(complex_event)?;
    println!("\n✅ EventLogger demonstration completed successfully!");
    println!("📄 Check 'demo_event.log' for the structured log output");
    println!("🔍 All events include JSON structured data for easy parsing and analysis");
    Ok(())
}