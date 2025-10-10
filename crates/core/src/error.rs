use thiserror::Error;

/// Main error type for the antivirus system
#[derive(Debug, Error)]
pub enum AntivirusError {
    #[error("Scan engine error: {0}")]
    ScanEngine(#[from] ScanEngineError),
    
    #[error("Quarantine operation failed: {0}")]
    Quarantine(#[from] QuarantineError),
    
    #[error("Update operation failed: {0}")]
    Update(#[from] UpdateError),
    
    #[error("Configuration error: {0}")]
    Configuration(#[from] ConfigError),
    
    #[error("Driver communication error: {0}")]
    Driver(#[from] DriverError),
    
    #[error("Network error: {0}")]
    Network(#[from] NetworkError),
    
    #[error("Email scanning error: {0}")]
    EmailScanning(#[from] EmailScanError),
    
    #[error("Database error: {0}")]
    Database(String),
    
    #[error("File not found: {0}")]
    FileNotFound(std::path::PathBuf),
    
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    
    #[error("Internal error: {0}")]
    Internal(String),
}

#[derive(Debug, Error)]
pub enum ScanEngineError {
    #[error("Signature database not loaded")]
    SignatureDatabaseNotLoaded,
    
    #[error("YARA engine error: {0}")]
    YaraEngine(String),
    
    #[error("Heuristic analysis failed: {0}")]
    HeuristicAnalysis(String),
    
    #[error("ML classification failed: {0}")]
    MLClassification(String),
    
    #[error("File access denied: {0}")]
    FileAccessDenied(String),
    
    #[error("Scan timeout")]
    ScanTimeout,
}

#[derive(Debug, Error)]
pub enum QuarantineError {
    #[error("Quarantine storage full")]
    StorageFull,
    
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
    
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
    
    #[error("Quarantine entry not found: {0}")]
    EntryNotFound(String),
    
    #[error("Restore failed: {0}")]
    RestoreFailed(String),
    
    #[error("File not found: {0}")]
    FileNotFound(String),
    
    #[error("Hash calculation failed: {0}")]
    HashCalculationFailed(String),
    
    #[error("Original file removal failed: {0}")]
    OriginalFileRemovalFailed(String),
    
    #[error("Deletion failed: {0}")]
    DeletionFailed(String),
    
    #[error("Database operation failed: {0}")]
    DatabaseError(String),
}

#[derive(Debug, Error)]
pub enum UpdateError {
    #[error("Download failed: {0}")]
    DownloadFailed(String),
    
    #[error("Network error: {0}")]
    NetworkError(String),
    
    #[error("I/O error: {0}")]
    IoError(String),
    
    #[error("Signature verification failed")]
    SignatureVerificationFailed,
    
    #[error("Integrity check failed: {0}")]
    IntegrityCheckFailed(String),
    
    #[error("Update package corrupted")]
    PackageCorrupted,
    
    #[error("Rollback failed: {0}")]
    RollbackFailed(String),
    
    #[error("No updates available")]
    NoUpdatesAvailable,
    
    #[error("Delta update failed: {0}")]
    DeltaUpdateFailed(String),
    
    #[error("Version mismatch: {0}")]
    VersionMismatch(String),
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("Configuration file not found: {0}")]
    FileNotFound(String),
    
    #[error("Invalid configuration format: {0}")]
    InvalidFormat(String),
    
    #[error("Missing required configuration: {0}")]
    MissingRequired(String),
    
    #[error("Configuration validation failed: {0}")]
    ValidationFailed(String),
}

#[derive(Debug, Error)]
pub enum DriverError {
    #[error("Driver not loaded")]
    DriverNotLoaded,
    
    #[error("Communication timeout")]
    CommunicationTimeout,
    
    #[error("Invalid driver response")]
    InvalidResponse,
    
    #[error("Driver operation failed: {0}")]
    OperationFailed(String),
}

#[derive(Debug, Error)]
pub enum NetworkError {
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),
    
    #[error("TLS handshake failed")]
    TlsHandshakeFailed,
    
    #[error("Request timeout")]
    RequestTimeout,
    
    #[error("Invalid response: {0}")]
    InvalidResponse(String),
}

#[derive(Debug, Error)]
pub enum EmailScanError {
    #[error("Email parsing failed: {0}")]
    EmailParsingFailed(String),
    
    #[error("Attachment extraction failed: {0}")]
    AttachmentExtractionFailed(String),
    
    #[error("MAPI initialization failed: {0}")]
    MapiInitializationFailed(String),
    
    #[error("Outlook integration failed: {0}")]
    OutlookIntegrationFailed(String),
    
    #[error("Email monitoring failed: {0}")]
    EmailMonitoringFailed(String),
    
    #[error("Attachment too large: {0} bytes")]
    AttachmentTooLarge(u64),
    
    #[error("Unsupported email format: {0}")]
    UnsupportedEmailFormat(String),
    
    #[error("Temporary file creation failed: {0}")]
    TempFileCreationFailed(String),
}

pub type Result<T> = std::result::Result<T, AntivirusError>;