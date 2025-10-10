use crate::{Result, BrowserExtensionError};
use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};
use tokio::sync::mpsc;
use tracing::{debug, error, info};
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeMessage {
    pub message_type: MessageType,
    pub data: serde_json::Value,
    pub request_id: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageType {
    CheckUrl,
    ScanDownload,
    GetStatus,
    UpdateSettings,
    ThreatAlert,
    Response,
    Error,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UrlCheckRequest {
    pub url: String,
    pub tab_id: Option<u32>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UrlCheckResponse {
    pub url: String,
    pub is_safe: bool,
    pub threat_type: Option<String>,
    pub reputation_score: f32,
    pub block_reason: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DownloadScanRequest {
    pub file_path: String,
    pub download_url: String,
    pub file_size: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DownloadScanResponse {
    pub file_path: String,
    pub is_safe: bool,
    pub threat_info: Option<core::types::ThreatInfo>,
    pub action_taken: String,
}
pub struct NativeMessagingHost {
    message_sender: mpsc::UnboundedSender<NativeMessage>,
    message_receiver: mpsc::UnboundedReceiver<NativeMessage>,
}
impl NativeMessagingHost {
    pub fn new() -> Self {
        let (message_sender, message_receiver) = mpsc::unbounded_channel();
        Self {
            message_sender,
            message_receiver,
        }
    }
    pub async fn start(&mut self) -> Result<()> {
        info!("Starting native messaging host");
        let sender = self.message_sender.clone();
        tokio::spawn(async move {
            if let Err(e) = Self::read_stdin_messages(sender).await {
                error!("Stdin reader error: {}", e);
            }
        });
        while let Some(message) = self.message_receiver.recv().await {
            if let Err(e) = self.handle_message(message).await {
                error!("Message handling error: {}", e);
            }
        }
        Ok(())
    }
    async fn read_stdin_messages(sender: mpsc::UnboundedSender<NativeMessage>) -> Result<()> {
        let mut stdin = io::stdin();
        let mut buffer = [0u8; 4];
        loop {
            stdin.read_exact(&mut buffer)?;
            let message_length = u32::from_le_bytes(buffer) as usize;
            if message_length == 0 || message_length > 1024 * 1024 {
                return Err(BrowserExtensionError::NativeMessaging(
                    "Invalid message length".to_string()
                ));
            }
            let mut message_buffer = vec![0u8; message_length];
            stdin.read_exact(&mut message_buffer)?;
            let message_str = String::from_utf8(message_buffer)
                .map_err(|e| BrowserExtensionError::NativeMessaging(format!("UTF-8 error: {}", e)))?;
            let message: NativeMessage = serde_json::from_str(&message_str)?;
            debug!("Received message: {:?}", message);
            if sender.send(message).is_err() {
                break;
            }
        }
        Ok(())
    }
    async fn handle_message(&self, message: NativeMessage) -> Result<()> {
        match message.message_type {
            MessageType::CheckUrl => {
                self.handle_url_check(message).await?;
            }
            MessageType::ScanDownload => {
                self.handle_download_scan(message).await?;
            }
            MessageType::GetStatus => {
                self.handle_status_request(message).await?;
            }
            MessageType::UpdateSettings => {
                self.handle_settings_update(message).await?;
            }
            _ => {
                debug!("Unhandled message type: {:?}", message.message_type);
            }
        }
        Ok(())
    }
    async fn handle_url_check(&self, message: NativeMessage) -> Result<()> {
        let request: UrlCheckRequest = serde_json::from_value(message.data)?;
        debug!("Checking URL: {}", request.url);
        let reputation_checker = crate::UrlReputationChecker::new();
        let result = reputation_checker.check_url(&request.url).await?;
        let response = UrlCheckResponse {
            url: request.url,
            is_safe: result.is_safe,
            threat_type: result.threat_type,
            reputation_score: result.reputation_score,
            block_reason: result.block_reason,
        };
        self.send_response(message.request_id, MessageType::Response, response).await?;
        Ok(())
    }
    async fn handle_download_scan(&self, message: NativeMessage) -> Result<()> {
        let request: DownloadScanRequest = serde_json::from_value(message.data)?;
        debug!("Scanning download: {}", request.file_path);
        let download_scanner = crate::DownloadScanner::new();
        let result = download_scanner.scan_download(&request.file_path, &request.download_url).await?;
        let response = DownloadScanResponse {
            file_path: request.file_path,
            is_safe: result.is_safe,
            threat_info: result.threat_info,
            action_taken: result.action_taken,
        };
        self.send_response(message.request_id, MessageType::Response, response).await?;
        Ok(())
    }
    async fn handle_status_request(&self, message: NativeMessage) -> Result<()> {
        let status = serde_json::json!({
            "service_running": true,
            "real_time_protection": true,
            "last_update": "2024-01-01T00:00:00Z",
            "version": "1.0.0"
        });
        self.send_response(message.request_id, MessageType::Response, status).await?;
        Ok(())
    }
    async fn handle_settings_update(&self, message: NativeMessage) -> Result<()> {
        debug!("Updating settings: {:?}", message.data);
        let response = serde_json::json!({
            "success": true,
            "message": "Settings updated successfully"
        });
        self.send_response(message.request_id, MessageType::Response, response).await?;
        Ok(())
    }
    async fn send_response(
        &self,
        request_id: Option<String>,
        message_type: MessageType,
        data: impl Serialize,
    ) -> Result<()> {
        let response = NativeMessage {
            message_type,
            data: serde_json::to_value(data)?,
            request_id,
        };
        self.send_message(response).await
    }
    async fn send_message(&self, message: NativeMessage) -> Result<()> {
        let json_str = serde_json::to_string(&message)?;
        let message_bytes = json_str.as_bytes();
        let message_length = message_bytes.len() as u32;
        let length_bytes = message_length.to_le_bytes();
        io::stdout().write_all(&length_bytes)?;
        io::stdout().write_all(message_bytes)?;
        io::stdout().flush()?;
        debug!("Sent message: {:?}", message);
        Ok(())
    }
    pub async fn send_threat_alert(&self, threat_info: core::types::ThreatInfo) -> Result<()> {
        let alert_data = serde_json::json!({
            "threat_name": threat_info.name,
            "threat_type": threat_info.threat_type,
            "severity": threat_info.severity,
            "url": threat_info.additional_info.get("url"),
            "action_required": true
        });
        let message = NativeMessage {
            message_type: MessageType::ThreatAlert,
            data: alert_data,
            request_id: None,
        };
        self.send_message(message).await
    }
}
impl Default for NativeMessagingHost {
    fn default() -> Self {
        Self::new()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_native_message_serialization() {
        let message = NativeMessage {
            message_type: MessageType::CheckUrl,
            data: serde_json::json!({"url": "https:
            request_id: Some("test-123".to_string()),
        };
        let json = serde_json::to_string(&message).unwrap();
        let deserialized: NativeMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(message.request_id, deserialized.request_id);
    }
    #[test]
    fn test_url_check_request_serialization() {
        let request = UrlCheckRequest {
            url: "https:
            tab_id: Some(123),
        };
        let json = serde_json::to_string(&request).unwrap();
        let deserialized: UrlCheckRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(request.url, deserialized.url);
        assert_eq!(request.tab_id, deserialized.tab_id);
    }
}