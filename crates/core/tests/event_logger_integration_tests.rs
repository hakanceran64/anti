use hadron_core::{
    EventLogger, StructuredEvent, EventSeverity, LoggingConfig, AuditEvent, AuditEventType, AuditResult,
    log_structured_security_event, log_security_event, SecurityEventSeverity
};
use tempfile::TempDir;
use chrono::Utc;
use serde_json;
fn create_test_logging_config() -> LoggingConfig {
    let temp_dir = TempDir::new().unwrap();
    let log_path = temp_dir.path().join("test_event.log");
    LoggingConfig {
        log_level: "info".to_string(),
        log_file_path: log_path,
        max_log_file_size_mb: 10,
        max_log_files: 5,
        enable_console_logging: false,
        enable_windows_event_log: false,
        enable_json_logging: true,
    }
}
#[test]
fn test_event_logger_initialization() {
    let config = create_test_logging_config();
    let event_logger = EventLogger::new(config);
    assert!(event_logger.is_ok());
    let event_logger = event_logger.unwrap();
    let init_result = event_logger.initialize();
    assert!(init_result.is_ok());
}
#[test]
fn test_structured_event_logging_comprehensive() {
    let config = create_test_logging_config();
    let event_logger = EventLogger::new(config).unwrap();
    let _ = event_logger.initialize();
    let severities = [
        EventSeverity::Debug,
        EventSeverity::Low,
        EventSeverity::Medium,
        EventSeverity::High,
        EventSeverity::Critical,
    ];
    for (i, severity) in severities.iter().enumerate() {
        let event = StructuredEvent::new(
            &format!("test_event_{}", i),
            *severity,
            "test_source",
            &format!("Test message for severity {:?}", severity),
        )
        .with_user("test_user")
        .with_correlation_id(&format!("corr-{}", i))
        .with_session_id(&format!("sess-{}", i));
        let result = event_logger.log_structured_event(event);
        assert!(result.is_ok(), "Failed to log event with severity {:?}", severity);
    }
    let stats = event_logger.get_event_statistics();
    assert_eq!(stats.len(), 5);
    for i in 0..5 {
        assert_eq!(stats.get(&format!("test_event_{}", i)), Some(&1));
    }
}
#[test]
fn test_audit_event_logging() {
    let config = create_test_logging_config();
    let event_logger = EventLogger::new(config).unwrap();
    let _ = event_logger.initialize();
    let audit_event = AuditEvent {
        event_type: AuditEventType::ScanOperation,
        user: "admin".to_string(),
        timestamp: Utc::now(),
        resource: "C:\\test\\file.exe".to_string(),
        action: "scan".to_string(),
        result: AuditResult::Success,
        details: Some(serde_json::json!({
            "scan_duration": 1500,
            "threats_found": 0
        })),
    };
    let result = event_logger.log_audit_event(audit_event);
    assert!(result.is_ok());
}
#[test]
fn test_security_event_logging_compatibility() {
    let config = create_test_logging_config();
    let event_logger = EventLogger::new(config).unwrap();
    let _ = event_logger.initialize();
    let details = serde_json::json!({
        "source_ip": "192.168.1.100",
        "user_agent": "TestAgent/1.0"
    });
    log_security_event(
        "authentication_failure",
        SecurityEventSeverity::High,
        "Failed login attempt detected",
        Some(&details),
    );
    let result = log_structured_security_event(
        &event_logger,
        "authentication_success",
        EventSeverity::Medium,
        "User successfully authenticated",
        Some("admin"),
        Some(details),
    );
    assert!(result.is_ok());
}
#[test]
fn test_log_rotation_functionality() {
    let config = create_test_logging_config();
    let event_logger = EventLogger::new(config).unwrap();
    let _ = event_logger.initialize();
    let archive_result = event_logger.archive_logs();
    assert!(archive_result.is_ok());
    let cleanup_result = event_logger.cleanup_old_logs(30);
    assert!(cleanup_result.is_ok());
}
#[test]
fn test_event_with_complex_details() {
    let config = create_test_logging_config();
    let event_logger = EventLogger::new(config).unwrap();
    let _ = event_logger.initialize();
    let complex_details = serde_json::json!({
        "scan_results": {
            "files_scanned": 1000,
            "threats_found": 5,
            "scan_duration_ms": 30000,
            "threats": [
                {
                    "name": "Trojan.Win32.Test",
                    "path": "C:\\malware\\test1.exe",
                    "severity": "high"
                },
                {
                    "name": "Adware.Generic",
                    "path": "C:\\temp\\suspicious.dll",
                    "severity": "medium"
                }
            ]
        },
        "system_info": {
            "os": "Windows 10",
            "cpu_usage": 25.5,
            "memory_usage": 1024
        }
    });
    let event = StructuredEvent::new(
        "comprehensive_scan_completed",
        EventSeverity::High,
        "scan_engine",
        "Comprehensive system scan completed with threats detected",
    )
    .with_user("system")
    .with_details(complex_details)
    .with_correlation_id("scan-12345")
    .with_session_id("session-67890");
    let result = event_logger.log_structured_event(event);
    assert!(result.is_ok());
    let stats = event_logger.get_event_statistics();
    assert_eq!(stats.get("comprehensive_scan_completed"), Some(&1));
}
#[test]
fn test_multiple_event_types_statistics() {
    let config = create_test_logging_config();
    let event_logger = EventLogger::new(config).unwrap();
    let _ = event_logger.initialize();
    for i in 0..3 {
        let event = StructuredEvent::new(
            "repeated_event",
            EventSeverity::Medium,
            "test_source",
            &format!("Repeated event number {}", i),
        );
        let result = event_logger.log_structured_event(event);
        assert!(result.is_ok());
    }
    let event_types = ["event_a", "event_b", "event_c"];
    for event_type in &event_types {
        let event = StructuredEvent::new(
            event_type,
            EventSeverity::Low,
            "test_source",
            &format!("Event of type {}", event_type),
        );
        let result = event_logger.log_structured_event(event);
        assert!(result.is_ok());
    }
    let stats = event_logger.get_event_statistics();
    assert_eq!(stats.get("repeated_event"), Some(&3));
    for event_type in &event_types {
        assert_eq!(stats.get(*event_type), Some(&1));
    }
}
#[test]
fn test_json_serialization_of_events() {
    let event = StructuredEvent::new(
        "serialization_test",
        EventSeverity::Medium,
        "test_source",
        "Testing JSON serialization",
    )
    .with_user("test_user")
    .with_details(serde_json::json!({
        "test_data": "value",
        "number": 42,
        "array": [1, 2, 3]
    }))
    .with_correlation_id("test-correlation")
    .with_session_id("test-session");
    let json_result = serde_json::to_string(&event);
    assert!(json_result.is_ok());
    let json_str = json_result.unwrap();
    assert!(json_str.contains("serialization_test"));
    assert!(json_str.contains("test_user"));
    assert!(json_str.contains("test-correlation"));
    let deserialized_result: Result<StructuredEvent, _> = serde_json::from_str(&json_str);
    assert!(deserialized_result.is_ok());
    let deserialized_event = deserialized_result.unwrap();
    assert_eq!(deserialized_event.event_type, event.event_type);
    assert_eq!(deserialized_event.user, event.user);
    assert_eq!(deserialized_event.correlation_id, event.correlation_id);
    assert_eq!(deserialized_event.session_id, event.session_id);
}