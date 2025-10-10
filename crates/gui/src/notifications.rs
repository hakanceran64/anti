/// Notification system for the GUI

use hadron_core::{ThreatInfo, ThreatSeverity};
use std::collections::VecDeque;
use chrono::{DateTime, Utc};

/// Notification types
#[derive(Debug, Clone)]
pub enum NotificationType {
    ThreatDetected(ThreatInfo),
    ScanCompleted { threats_found: u32, files_scanned: u64 },
    UpdateAvailable { version: String },
    UpdateCompleted { version: String },
    QuarantineAction { action: String, file_name: String },
    SystemError { message: String },
    Info { message: String },
}

/// Notification item
#[derive(Debug, Clone)]
pub struct Notification {
    pub id: uuid::Uuid,
    pub notification_type: NotificationType,
    pub timestamp: DateTime<Utc>,
    pub is_read: bool,
    pub auto_dismiss_after: Option<std::time::Duration>,
}

impl Notification {
    pub fn new(notification_type: NotificationType) -> Self {
        let auto_dismiss_after = match &notification_type {
            NotificationType::ThreatDetected(_) => None, // Don't auto-dismiss threats
            NotificationType::SystemError { .. } => None, // Don't auto-dismiss errors
            _ => Some(std::time::Duration::from_secs(10)), // Auto-dismiss info notifications
        };

        Self {
            id: uuid::Uuid::new_v4(),
            notification_type,
            timestamp: Utc::now(),
            is_read: false,
            auto_dismiss_after,
        }
    }

    pub fn get_title(&self) -> String {
        match &self.notification_type {
            NotificationType::ThreatDetected(threat) => {
                format!("Threat Detected: {}", threat.name)
            }
            NotificationType::ScanCompleted { threats_found, .. } => {
                if *threats_found > 0 {
                    format!("Scan Completed - {} threats found", threats_found)
                } else {
                    "Scan Completed - No threats found".to_string()
                }
            }
            NotificationType::UpdateAvailable { version } => {
                format!("Update Available: {}", version)
            }
            NotificationType::UpdateCompleted { version } => {
                format!("Update Completed: {}", version)
            }
            NotificationType::QuarantineAction { action, file_name } => {
                format!("Quarantine: {} {}", action, file_name)
            }
            NotificationType::SystemError { .. } => {
                "System Error".to_string()
            }
            NotificationType::Info { .. } => {
                "Information".to_string()
            }
        }
    }

    pub fn get_message(&self) -> String {
        match &self.notification_type {
            NotificationType::ThreatDetected(threat) => {
                format!(
                    "Threat '{}' detected in file: {}\nSeverity: {:?}\nAction: File quarantined",
                    threat.name,
                    threat.file_path.display(),
                    threat.severity
                )
            }
            NotificationType::ScanCompleted { threats_found, files_scanned } => {
                format!(
                    "Scan completed successfully.\nFiles scanned: {}\nThreats found: {}",
                    files_scanned, threats_found
                )
            }
            NotificationType::UpdateAvailable { version } => {
                format!("A new update ({}) is available for download.", version)
            }
            NotificationType::UpdateCompleted { version } => {
                format!("Successfully updated to version {}.", version)
            }
            NotificationType::QuarantineAction { action, file_name } => {
                format!("Successfully {} file: {}", action, file_name)
            }
            NotificationType::SystemError { message } => {
                message.clone()
            }
            NotificationType::Info { message } => {
                message.clone()
            }
        }
    }

    pub fn get_severity(&self) -> NotificationSeverity {
        match &self.notification_type {
            NotificationType::ThreatDetected(threat) => {
                match threat.severity {
                    ThreatSeverity::Critical => NotificationSeverity::Critical,
                    ThreatSeverity::High => NotificationSeverity::High,
                    ThreatSeverity::Medium => NotificationSeverity::Medium,
                    ThreatSeverity::Low => NotificationSeverity::Low,
                }
            }
            NotificationType::ScanCompleted { threats_found, .. } => {
                if *threats_found > 0 {
                    NotificationSeverity::Medium
                } else {
                    NotificationSeverity::Info
                }
            }
            NotificationType::SystemError { .. } => NotificationSeverity::High,
            _ => NotificationSeverity::Info,
        }
    }

    pub fn should_auto_dismiss(&self) -> bool {
        if let Some(duration) = self.auto_dismiss_after {
            let elapsed = Utc::now().signed_duration_since(self.timestamp);
            elapsed.to_std().unwrap_or_default() > duration
        } else {
            false
        }
    }
}

/// Notification severity levels
#[derive(Debug, Clone, PartialEq)]
pub enum NotificationSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl NotificationSeverity {
    pub fn get_color(&self) -> eframe::egui::Color32 {
        match self {
            NotificationSeverity::Info => eframe::egui::Color32::BLUE,
            NotificationSeverity::Low => eframe::egui::Color32::GREEN,
            NotificationSeverity::Medium => eframe::egui::Color32::YELLOW,
            NotificationSeverity::High => eframe::egui::Color32::from_rgb(255, 165, 0), // Orange
            NotificationSeverity::Critical => eframe::egui::Color32::RED,
        }
    }
}

/// Notification manager
pub struct NotificationManager {
    notifications: VecDeque<Notification>,
    max_notifications: usize,
    show_notifications: bool,
}

impl NotificationManager {
    pub fn new() -> Self {
        Self {
            notifications: VecDeque::new(),
            max_notifications: 50,
            show_notifications: true,
        }
    }

    /// Add a new notification
    pub fn add_notification(&mut self, notification_type: NotificationType) {
        let notification = Notification::new(notification_type);
        
        // Add to front of queue
        self.notifications.push_front(notification);
        
        // Limit the number of notifications
        while self.notifications.len() > self.max_notifications {
            self.notifications.pop_back();
        }
    }

    /// Get all notifications
    pub fn get_notifications(&self) -> &VecDeque<Notification> {
        &self.notifications
    }

    /// Mark notification as read
    pub fn mark_as_read(&mut self, notification_id: uuid::Uuid) {
        if let Some(notification) = self.notifications.iter_mut()
            .find(|n| n.id == notification_id) {
            notification.is_read = true;
        }
    }

    /// Remove notification
    pub fn remove_notification(&mut self, notification_id: uuid::Uuid) {
        self.notifications.retain(|n| n.id != notification_id);
    }

    /// Clear all notifications
    pub fn clear_all(&mut self) {
        self.notifications.clear();
    }

    /// Update notifications (remove auto-dismiss ones)
    pub fn update(&mut self) {
        self.notifications.retain(|n| !n.should_auto_dismiss());
    }

    /// Get unread notification count
    pub fn get_unread_count(&self) -> usize {
        self.notifications.iter().filter(|n| !n.is_read).count()
    }

    /// Show notification panel in GUI
    pub fn show_notification_panel(&mut self, ui: &mut eframe::egui::Ui) {
        ui.heading("Notifications");
        ui.separator();

        if self.notifications.is_empty() {
            ui.label("No notifications");
            return;
        }

        // Clear all button
        ui.horizontal(|ui| {
            if ui.button("Clear All").clicked() {
                self.clear_all();
            }
            
            ui.separator();
            ui.label(format!("Total: {}", self.notifications.len()));
            
            let unread_count = self.get_unread_count();
            if unread_count > 0 {
                ui.label(format!("Unread: {}", unread_count));
            }
        });

        ui.add_space(5.0);

        // Notification list
        eframe::egui::ScrollArea::vertical().show(ui, |ui| {
            let mut to_remove = Vec::new();
            
            for notification in &mut self.notifications {
                let severity = notification.get_severity();
                let color = severity.get_color();
                
                ui.group(|ui| {
                    ui.horizontal(|ui| {
                        // Severity indicator
                        ui.colored_label(color, "●");
                        
                        // Title and timestamp
                        ui.vertical(|ui| {
                            ui.horizontal(|ui| {
                                ui.label(&notification.get_title());
                                ui.with_layout(eframe::egui::Layout::right_to_left(eframe::egui::Align::Center), |ui| {
                                    ui.label(notification.timestamp.format("%H:%M:%S").to_string());
                                    
                                    if ui.small_button("×").clicked() {
                                        to_remove.push(notification.id);
                                    }
                                });
                            });
                            
                            // Message
                            ui.label(&notification.get_message());
                            
                            // Mark as read button
                            if !notification.is_read {
                                if ui.small_button("Mark as read").clicked() {
                                    notification.is_read = true;
                                }
                            }
                        });
                    });
                });
                
                ui.add_space(5.0);
            }
            
            // Remove notifications marked for deletion
            for id in to_remove {
                self.remove_notification(id);
            }
        });
    }

    /// Show notification toast (overlay)
    pub fn show_notification_toast(&self, ctx: &eframe::egui::Context) {
        if !self.show_notifications {
            return;
        }

        // Show multiple recent unread notifications as toasts
        let mut toast_count = 0;
        for notification in self.notifications.iter().take(3) {
            if !notification.is_read && toast_count < 3 {
                let severity = notification.get_severity();
                
                // Show toasts for medium and higher severity notifications
                if matches!(severity, NotificationSeverity::Medium | NotificationSeverity::High | NotificationSeverity::Critical) {
                    let y_offset = 10.0 + (toast_count as f32 * 120.0);
                    
                    eframe::egui::Window::new(format!("Notification_{}", notification.id))
                        .title_bar(false)
                        .collapsible(false)
                        .resizable(false)
                        .anchor(eframe::egui::Align2::RIGHT_TOP, eframe::egui::vec2(-10.0, y_offset))
                        .fixed_size(eframe::egui::vec2(300.0, 100.0))
                        .show(ctx, |ui| {
                            // Toast header with severity indicator and close button
                            ui.horizontal(|ui| {
                                ui.colored_label(severity.get_color(), "●");
                                ui.strong(&notification.get_title());
                                ui.with_layout(eframe::egui::Layout::right_to_left(eframe::egui::Align::Center), |ui| {
                                    if ui.small_button("×").clicked() {
                                        // Mark as read when closed
                                        // Note: This would need to be handled in the main app
                                    }
                                });
                            });
                            
                            ui.separator();
                            
                            // Toast message
                            ui.label(&notification.get_message());
                            
                            // Toast timestamp
                            ui.with_layout(eframe::egui::Layout::right_to_left(eframe::egui::Align::Min), |ui| {
                                ui.small(notification.timestamp.format("%H:%M:%S").to_string());
                            });
                        });
                    
                    toast_count += 1;
                }
            }
        }
    }

    /// Enable/disable notifications
    pub fn set_notifications_enabled(&mut self, enabled: bool) {
        self.show_notifications = enabled;
    }
}

impl Default for NotificationManager {
    fn default() -> Self {
        Self::new()
    }
}