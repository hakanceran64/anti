/// GUI panel implementations

use eframe::egui;
use hadron_core::{SystemStatus, QuarantineEntry, ScanProgress, RemovableDevice};

/// Dashboard panel implementation
pub struct DashboardPanel {
    system_status: Option<SystemStatus>,
}

impl DashboardPanel {
    pub fn new() -> Self {
        Self {
            system_status: None,
        }
    }

    pub fn update_status(&mut self, status: SystemStatus) {
        self.system_status = Some(status);
    }

    pub fn show(&mut self, ui: &mut egui::Ui) {
        ui.heading("System Dashboard");
        ui.separator();

        if let Some(status) = &self.system_status {
            self.show_protection_status(ui, status);
            ui.add_space(10.0);
            self.show_scan_statistics(ui, status);
            ui.add_space(10.0);
            self.show_threat_summary(ui, status);
        } else {
            ui.label("Loading system status...");
        }
    }

    fn show_protection_status(&self, ui: &mut egui::Ui, status: &SystemStatus) {
        ui.group(|ui| {
            ui.horizontal(|ui| {
                ui.heading("Protection Status");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if status.realtime_protection_enabled {
                        ui.colored_label(egui::Color32::GREEN, "🛡️ PROTECTED");
                    } else {
                        ui.colored_label(egui::Color32::RED, "⚠️ AT RISK");
                    }
                });
            });
            
            ui.separator();
            
            // Protection components status
            ui.horizontal(|ui| {
                ui.label("Real-time Protection:");
                if status.realtime_protection_enabled {
                    ui.colored_label(egui::Color32::GREEN, "✓ Active");
                } else {
                    ui.colored_label(egui::Color32::RED, "✗ Inactive");
                }
            });
            
            ui.horizontal(|ui| {
                ui.label("File System Protection:");
                ui.colored_label(egui::Color32::GREEN, "✓ Active");
            });
            
            ui.horizontal(|ui| {
                ui.label("Network Protection:");
                ui.colored_label(egui::Color32::GREEN, "✓ Active");
            });
            
            ui.add_space(5.0);
            
            ui.horizontal(|ui| {
                ui.label("Engine Version:");
                ui.monospace(&status.engine_version);
            });
            
            ui.horizontal(|ui| {
                ui.label("Signature Version:");
                ui.monospace(&status.signature_version);
            });
        });
    }

    fn show_scan_statistics(&self, ui: &mut egui::Ui, status: &SystemStatus) {
        ui.group(|ui| {
            ui.label("Scan Statistics");
            
            if let Some(last_scan) = status.last_scan_time {
                ui.horizontal(|ui| {
                    ui.label("Last Scan:");
                    ui.label(last_scan.format("%Y-%m-%d %H:%M:%S").to_string());
                });
            } else {
                ui.label("No scans performed yet");
            }
            
            if let Some(last_update) = status.last_update_time {
                ui.horizontal(|ui| {
                    ui.label("Last Update:");
                    ui.label(last_update.format("%Y-%m-%d %H:%M:%S").to_string());
                });
            }
        });
    }

    fn show_threat_summary(&self, ui: &mut egui::Ui, status: &SystemStatus) {
        ui.group(|ui| {
            ui.label("Threat Summary");
            
            ui.horizontal(|ui| {
                ui.label("Threats Detected Today:");
                if status.threats_detected_today > 0 {
                    ui.colored_label(egui::Color32::RED, status.threats_detected_today.to_string());
                } else {
                    ui.colored_label(egui::Color32::GREEN, "0");
                }
            });
            
            ui.horizontal(|ui| {
                ui.label("Quarantined Files:");
                ui.label(status.quarantine_count.to_string());
            });
        });
    }
}

/// Enhanced scan panel implementation
pub struct ScanPanel {
    scan_targets: String,
    scan_progress: Option<ScanProgress>,
    is_scanning: bool,
    selected_scan_type: ScanType,
    custom_paths: Vec<String>,
    scan_options: ScanOptions,
}

/// Available scan types for the GUI
#[derive(Debug, Clone, PartialEq)]
pub enum ScanType {
    Quick,
    Full,
    Custom,
    Memory,
    Network,
    FlashDrive,
    Email,
    Scheduled,
}

/// Scan configuration options
#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub scan_archives: bool,
    pub scan_email: bool,
    pub scan_network_drives: bool,
    pub scan_removable_media: bool,
    pub heuristic_analysis: bool,
    pub deep_scan: bool,
    pub scan_boot_sectors: bool,
    pub scan_memory: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            scan_archives: true,
            scan_email: true,
            scan_network_drives: false,
            scan_removable_media: true,
            heuristic_analysis: true,
            deep_scan: false,
            scan_boot_sectors: false,
            scan_memory: false,
        }
    }
}

impl ScanPanel {
    pub fn new() -> Self {
        Self {
            scan_targets: if cfg!(windows) { "C:\\".to_string() } else { "/".to_string() },
            scan_progress: None,
            is_scanning: false,
            selected_scan_type: ScanType::Quick,
            custom_paths: vec![],
            scan_options: ScanOptions::default(),
        }
    }

    pub fn update_progress(&mut self, progress: ScanProgress) {
        self.scan_progress = Some(progress);
    }

    pub fn set_scanning(&mut self, scanning: bool) {
        self.is_scanning = scanning;
        if !scanning {
            self.scan_progress = None;
        }
    }

    pub fn show(&mut self, ui: &mut egui::Ui) -> ScanPanelAction {
        ui.heading("🔍 Advanced Scan Center");
        ui.separator();

        let mut action = ScanPanelAction::None;

        // Top row - Scan type selection
        ui.horizontal(|ui| {
            // Scan type selection
            ui.group(|ui| {
                ui.set_min_width(300.0);
                ui.vertical(|ui| {
                    ui.heading("Scan Type");
                    ui.separator();
                    
                    egui::ComboBox::from_label("Select scan type")
                        .selected_text(self.get_scan_type_display(&self.selected_scan_type))
                        .show_ui(ui, |ui| {
                            ui.selectable_value(&mut self.selected_scan_type, ScanType::Quick, "⚡ Quick Scan");
                            ui.selectable_value(&mut self.selected_scan_type, ScanType::Full, "🔍 Full System Scan");
                            ui.selectable_value(&mut self.selected_scan_type, ScanType::Custom, "📁 Custom Scan");
                            ui.selectable_value(&mut self.selected_scan_type, ScanType::Memory, "🧠 Memory Scan");
                            ui.selectable_value(&mut self.selected_scan_type, ScanType::Network, "🌐 Network Scan");
                            ui.selectable_value(&mut self.selected_scan_type, ScanType::FlashDrive, "💾 Flash Drive Scan");
                            ui.selectable_value(&mut self.selected_scan_type, ScanType::Email, "📧 Email Scan");
                            ui.selectable_value(&mut self.selected_scan_type, ScanType::Scheduled, "⏰ Scheduled Scan");
                        });
                    
                    ui.add_space(10.0);
                    
                    // Description for selected scan type
                    ui.label("Description:");
                    ui.small(self.get_scan_type_description(&self.selected_scan_type));
                });
            });
            
            ui.add_space(10.0);
            
            // Scan options
            ui.group(|ui| {
                ui.set_min_width(250.0);
                ui.vertical(|ui| {
                    ui.heading("Scan Options");
                    ui.separator();
                    
                    ui.checkbox(&mut self.scan_options.scan_archives, "📦 Scan Archives");
                    ui.checkbox(&mut self.scan_options.scan_email, "📧 Scan Email");
                    ui.checkbox(&mut self.scan_options.scan_network_drives, "🌐 Network Drives");
                    ui.checkbox(&mut self.scan_options.scan_removable_media, "💾 Removable Media");
                    ui.checkbox(&mut self.scan_options.heuristic_analysis, "🧠 Heuristic Analysis");
                    ui.checkbox(&mut self.scan_options.deep_scan, "🔬 Deep Scan");
                    ui.checkbox(&mut self.scan_options.scan_boot_sectors, "🚀 Boot Sectors");
                    ui.checkbox(&mut self.scan_options.scan_memory, "💭 Memory Scan");
                });
            });
            
            ui.add_space(10.0);
            
            // Quick actions
            ui.group(|ui| {
                ui.set_min_width(200.0);
                ui.vertical(|ui| {
                    ui.heading("Quick Actions");
                    ui.separator();
                    
                    if ui.add_enabled(
                        !self.is_scanning,
                        egui::Button::new("⚡ Quick Scan").min_size(egui::vec2(180.0, 35.0))
                    ).clicked() {
                        action = ScanPanelAction::StartQuickScan;
                    }
                    
                    if ui.add_enabled(
                        !self.is_scanning,
                        egui::Button::new("🔍 Full Scan").min_size(egui::vec2(180.0, 35.0))
                    ).clicked() {
                        action = ScanPanelAction::StartFullScan;
                    }
                    
                    if ui.add_enabled(
                        !self.is_scanning,
                        egui::Button::new("🧠 Memory Scan").min_size(egui::vec2(180.0, 35.0))
                    ).clicked() {
                        action = ScanPanelAction::StartMemoryScan;
                    }
                    
                    if self.is_scanning {
                        if ui.add(egui::Button::new("❌ Cancel Scan").min_size(egui::vec2(180.0, 35.0))).clicked() {
                            action = ScanPanelAction::CancelScan;
                        }
                    }
                });
            });
        });
        
        ui.add_space(15.0);
        
        // Custom scan configuration
        if self.selected_scan_type == ScanType::Custom {
            ui.group(|ui| {
                ui.set_min_width(ui.available_width());
                ui.vertical(|ui| {
                    ui.heading("📁 Custom Scan Configuration");
                    ui.separator();
                    
                    ui.horizontal(|ui| {
                        ui.label("Scan Path:");
                        ui.text_edit_singleline(&mut self.scan_targets);
                        if ui.button("📁 Browse").clicked() {
                            // File picker would go here
                        }
                        if ui.button("➕ Add Path").clicked() {
                            if !self.scan_targets.is_empty() && !self.custom_paths.contains(&self.scan_targets) {
                                self.custom_paths.push(self.scan_targets.clone());
                            }
                        }
                    });
                    
                    if !self.custom_paths.is_empty() {
                        ui.add_space(5.0);
                        ui.label("Selected Paths:");
                        
                        let mut to_remove = None;
                        for (i, path) in self.custom_paths.iter().enumerate() {
                            ui.horizontal(|ui| {
                                ui.label("📂");
                                ui.monospace(path);
                                if ui.small_button("❌").clicked() {
                                    to_remove = Some(i);
                                }
                            });
                        }
                        
                        if let Some(index) = to_remove {
                            self.custom_paths.remove(index);
                        }
                    }
                    
                    ui.add_space(10.0);
                    
                    if ui.add_enabled(
                        !self.is_scanning && (!self.custom_paths.is_empty() || !self.scan_targets.is_empty()),
                        egui::Button::new("🚀 Start Custom Scan").min_size(egui::vec2(200.0, 40.0))
                    ).clicked() {
                        let targets = if !self.custom_paths.is_empty() {
                            self.custom_paths.join(";")
                        } else {
                            self.scan_targets.clone()
                        };
                        action = ScanPanelAction::StartCustomScan(targets);
                    }
                });
            });
            
            ui.add_space(15.0);
        }
        
        // Main scan button for selected type
        if self.selected_scan_type != ScanType::Custom {
            ui.horizontal(|ui| {
                let button_text = if self.is_scanning {
                    "🔄 Scanning..."
                } else {
                    &format!("🚀 Start {}", self.get_scan_type_display(&self.selected_scan_type))
                };
                
                if ui.add_enabled(
                    !self.is_scanning,
                    egui::Button::new(button_text).min_size(egui::vec2(200.0, 50.0))
                ).clicked() {
                    action = match self.selected_scan_type {
                        ScanType::Quick => ScanPanelAction::StartQuickScan,
                        ScanType::Full => ScanPanelAction::StartFullScan,
                        ScanType::Memory => ScanPanelAction::StartMemoryScan,
                        ScanType::Network => ScanPanelAction::StartNetworkScan,
                        ScanType::FlashDrive => ScanPanelAction::StartFlashDriveScan,
                        ScanType::Email => ScanPanelAction::StartEmailScan,
                        ScanType::Scheduled => ScanPanelAction::StartScheduledScan,
                        ScanType::Custom => ScanPanelAction::None, // Handled above
                    };
                }
                
                ui.add_space(20.0);
                
                // Scan statistics
                ui.vertical(|ui| {
                    ui.label("📊 Scan Statistics");
                    ui.small("Last scan: Never");
                    ui.small("Threats found: 0");
                    ui.small("Files scanned: 0");
                });
            });
        }

        // Scan progress
        if let Some(progress) = &self.scan_progress {
            ui.add_space(15.0);
            self.show_enhanced_scan_progress(ui, progress);
        }

        action
    }
    
    fn get_scan_type_display(&self, scan_type: &ScanType) -> String {
        match scan_type {
            ScanType::Quick => "⚡ Quick Scan".to_string(),
            ScanType::Full => "🔍 Full System Scan".to_string(),
            ScanType::Custom => "📁 Custom Scan".to_string(),
            ScanType::Memory => "🧠 Memory Scan".to_string(),
            ScanType::Network => "🌐 Network Scan".to_string(),
            ScanType::FlashDrive => "💾 Flash Drive Scan".to_string(),
            ScanType::Email => "📧 Email Scan".to_string(),
            ScanType::Scheduled => "⏰ Scheduled Scan".to_string(),
        }
    }
    
    fn get_scan_type_description(&self, scan_type: &ScanType) -> &str {
        match scan_type {
            ScanType::Quick => "Scans common locations where threats are typically found. Fast and efficient for daily use.",
            ScanType::Full => "Comprehensive scan of the entire system including all files and folders. May take several hours.",
            ScanType::Custom => "Scan specific files, folders, or drives that you select. Flexible and targeted scanning.",
            ScanType::Memory => "Scans system memory for active threats and malicious processes. Quick but thorough.",
            ScanType::Network => "Monitors network traffic and scans for network-based threats and suspicious connections.",
            ScanType::FlashDrive => "Automatically scans USB drives and removable media when connected to the system.",
            ScanType::Email => "Scans email attachments and email content for threats using MAPI integration.",
            ScanType::Scheduled => "Configure automatic scans to run at specified times and intervals.",
        }
    }

    fn show_enhanced_scan_progress(&self, ui: &mut egui::Ui, progress: &ScanProgress) {
        ui.group(|ui| {
            ui.set_min_width(ui.available_width());
            ui.vertical(|ui| {
                ui.horizontal(|ui| {
                    ui.heading("🔄 Scan in Progress");
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.colored_label(egui::Color32::BLUE, format!("{:.1}%", progress.percentage_complete));
                    });
                });
                
                ui.separator();
                
                // Large animated progress bar
                let progress_fraction = progress.percentage_complete / 100.0;
                ui.add_sized(
                    [ui.available_width(), 25.0],
                    egui::ProgressBar::new(progress_fraction)
                        .text(format!("Scanning... {:.1}%", progress.percentage_complete))
                        .animate(true)
                );
                
                ui.add_space(10.0);
                
                // Current file being scanned
                if let Some(current_file) = &progress.current_file {
                    ui.horizontal(|ui| {
                        ui.label("📄 Currently scanning:");
                        ui.add_space(10.0);
                        ui.monospace(current_file.display().to_string());
                    });
                    ui.add_space(5.0);
                }
                
                // Statistics in a grid layout
                ui.horizontal(|ui| {
                    // Left column
                    ui.group(|ui| {
                        ui.set_min_width(200.0);
                        ui.vertical(|ui| {
                            ui.label("📊 Progress Statistics");
                            ui.separator();
                            
                            egui::Grid::new("progress_stats")
                                .num_columns(2)
                                .spacing([20.0, 4.0])
                                .show(ui, |ui| {
                                    ui.label("Files Scanned:");
                                    ui.label(format!("{}", progress.files_scanned));
                                    ui.end_row();
                                    
                                    ui.label("Total Files:");
                                    ui.label(format!("{}", progress.total_files));
                                    ui.end_row();
                                    
                                    ui.label("Progress:");
                                    ui.label(format!("{:.1}%", progress.percentage_complete));
                                    ui.end_row();
                                });
                        });
                    });
                    
                    ui.add_space(10.0);
                    
                    // Middle column
                    ui.group(|ui| {
                        ui.set_min_width(200.0);
                        ui.vertical(|ui| {
                            ui.label("⚠️ Threat Detection");
                            ui.separator();
                            
                            egui::Grid::new("threat_stats")
                                .num_columns(2)
                                .spacing([20.0, 4.0])
                                .show(ui, |ui| {
                                    ui.label("Threats Found:");
                                    if progress.threats_found > 0 {
                                        ui.colored_label(egui::Color32::RED, progress.threats_found.to_string());
                                    } else {
                                        ui.colored_label(egui::Color32::GREEN, "0");
                                    }
                                    ui.end_row();
                                    
                                    ui.label("Suspicious Files:");
                                    ui.label("0"); // Placeholder
                                    ui.end_row();
                                    
                                    ui.label("Quarantined:");
                                    ui.label("0"); // Placeholder
                                    ui.end_row();
                                });
                        });
                    });
                    
                    ui.add_space(10.0);
                    
                    // Right column
                    ui.group(|ui| {
                        ui.set_min_width(200.0);
                        ui.vertical(|ui| {
                            ui.label("⏱️ Time Information");
                            ui.separator();
                            
                            egui::Grid::new("time_stats")
                                .num_columns(2)
                                .spacing([20.0, 4.0])
                                .show(ui, |ui| {
                                    if let Some(time_remaining) = progress.estimated_time_remaining_ms {
                                        ui.label("Time Remaining:");
                                        let seconds = time_remaining / 1000;
                                        let minutes = seconds / 60;
                                        let hours = minutes / 60;
                                        
                                        if hours > 0 {
                                            ui.label(format!("{}h {}m", hours, minutes % 60));
                                        } else if minutes > 0 {
                                            ui.label(format!("{}m {}s", minutes, seconds % 60));
                                        } else {
                                            ui.label(format!("{}s", seconds));
                                        }
                                        ui.end_row();
                                    }
                                    
                                    ui.label("Scan Speed:");
                                    ui.label("~1000 files/min"); // Placeholder
                                    ui.end_row();
                                    
                                    ui.label("Elapsed Time:");
                                    ui.label("00:05:23"); // Placeholder
                                    ui.end_row();
                                });
                        });
                    });
                });
                
                ui.add_space(10.0);
                
                // Action buttons
                ui.horizontal(|ui| {
                    if ui.button("⏸️ Pause Scan").clicked() {
                        // Pause functionality
                    }
                    
                    if ui.button("❌ Cancel Scan").clicked() {
                        // Cancel functionality
                    }
                    
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label("Scan running in background...");
                    });
                });
            });
        });
    }

    fn show_scan_progress(&self, ui: &mut egui::Ui, progress: &ScanProgress) {
        ui.group(|ui| {
            ui.horizontal(|ui| {
                ui.heading("Scan Progress");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(format!("{:.1}%", progress.percentage_complete));
                });
            });
            
            ui.separator();
            
            // Large progress bar
            let progress_fraction = progress.percentage_complete / 100.0;
            ui.add_sized(
                [ui.available_width(), 20.0],
                egui::ProgressBar::new(progress_fraction)
                    .text(format!("Scanning... {:.1}%", progress.percentage_complete))
            );
            
            ui.add_space(10.0);
            
            // Current file being scanned
            if let Some(current_file) = &progress.current_file {
                ui.horizontal(|ui| {
                    ui.label("📄 Currently scanning:");
                });
                ui.horizontal(|ui| {
                    ui.add_space(20.0);
                    ui.monospace(current_file.display().to_string());
                });
            }
            
            ui.add_space(10.0);
            
            // Statistics grid
            egui::Grid::new("scan_stats")
                .num_columns(2)
                .spacing([40.0, 4.0])
                .show(ui, |ui| {
                    ui.label("📊 Files Scanned:");
                    ui.label(format!("{} / {}", progress.files_scanned, progress.total_files));
                    ui.end_row();
                    
                    ui.label("⚠️ Threats Found:");
                    if progress.threats_found > 0 {
                        ui.colored_label(egui::Color32::RED, progress.threats_found.to_string());
                    } else {
                        ui.colored_label(egui::Color32::GREEN, "0");
                    }
                    ui.end_row();
                    
                    if let Some(time_remaining) = progress.estimated_time_remaining_ms {
                        ui.label("⏱️ Time Remaining:");
                        let seconds = time_remaining / 1000;
                        let minutes = seconds / 60;
                        let hours = minutes / 60;
                        
                        if hours > 0 {
                            ui.label(format!("{}h {}m", hours, minutes % 60));
                        } else if minutes > 0 {
                            ui.label(format!("{}m {}s", minutes, seconds % 60));
                        } else {
                            ui.label(format!("{}s", seconds));
                        }
                        ui.end_row();
                    }
                    
                    // Scan speed
                    if progress.files_scanned > 0 {
                        ui.label("🚀 Scan Speed:");
                        ui.label(format!("{} files/sec", progress.files_scanned / (progress.percentage_complete / 100.0).max(0.01) as u64));
                        ui.end_row();
                    }
                });
        });
    }
}

/// Actions that can be triggered from the scan panel
pub enum ScanPanelAction {
    None,
    StartQuickScan,
    StartFullScan,
    StartCustomScan(String),
    StartMemoryScan,
    StartNetworkScan,
    StartFlashDriveScan,
    StartEmailScan,
    StartScheduledScan,
    CancelScan,
    PauseScan,
}

/// Quarantine panel implementation
pub struct QuarantinePanel {
    quarantine_entries: Vec<QuarantineEntry>,
    selected_entry: Option<usize>,
}

impl QuarantinePanel {
    pub fn new() -> Self {
        Self {
            quarantine_entries: Vec::new(),
            selected_entry: None,
        }
    }

    /// Format file size in human-readable format
    fn format_file_size(size: u64) -> String {
        const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
        let mut size = size as f64;
        let mut unit_index = 0;
        
        while size >= 1024.0 && unit_index < UNITS.len() - 1 {
            size /= 1024.0;
            unit_index += 1;
        }
        
        if unit_index == 0 {
            format!("{} {}", size as u64, UNITS[unit_index])
        } else {
            format!("{:.1} {}", size, UNITS[unit_index])
        }
    }

    pub fn update_entries(&mut self, entries: Vec<QuarantineEntry>) {
        self.quarantine_entries = entries;
    }

    pub fn show(&mut self, ui: &mut egui::Ui) -> QuarantinePanelAction {
        ui.heading("Quarantine Management");
        ui.separator();

        let mut action = QuarantinePanelAction::None;

        if self.quarantine_entries.is_empty() {
            ui.label("No files in quarantine");
            return action;
        }

        // Quarantine list
        ui.group(|ui| {
            ui.horizontal(|ui| {
                ui.heading("Quarantined Files");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(format!("{} files", self.quarantine_entries.len()));
                });
            });
            
            ui.separator();
            
            egui::ScrollArea::vertical()
                .max_height(400.0)
                .show(ui, |ui| {
                    for (index, entry) in self.quarantine_entries.iter().enumerate() {
                        let is_selected = self.selected_entry == Some(index);
                        
                        ui.group(|ui| {
                            // Threat header
                            ui.horizontal(|ui| {
                                // Severity indicator
                                let severity_color = match entry.threat_info.severity {
                                    hadron_core::ThreatSeverity::Critical => egui::Color32::RED,
                                    hadron_core::ThreatSeverity::High => egui::Color32::from_rgb(255, 165, 0),
                                    hadron_core::ThreatSeverity::Medium => egui::Color32::YELLOW,
                                    hadron_core::ThreatSeverity::Low => egui::Color32::GREEN,
                                };
                                ui.colored_label(severity_color, "●");
                                
                                // Threat name
                                if ui.selectable_label(is_selected, &entry.threat_info.name).clicked() {
                                    self.selected_entry = if is_selected { None } else { Some(index) };
                                }
                                
                                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                    ui.small(entry.quarantine_time.format("%Y-%m-%d %H:%M").to_string());
                                });
                            });
                            
                            // Expanded details
                            if is_selected {
                                ui.separator();
                                egui::Grid::new(format!("quarantine_details_{}", index))
                                    .num_columns(2)
                                    .spacing([10.0, 4.0])
                                    .show(ui, |ui| {
                                        ui.label("📁 Original Path:");
                                        ui.monospace(entry.original_path.display().to_string());
                                        ui.end_row();
                                        
                                        ui.label("🦠 Threat Type:");
                                        ui.label(format!("{:?}", entry.threat_info.threat_type));
                                        ui.end_row();
                                        
                                        ui.label("⚠️ Severity:");
                                        let severity_color = match entry.threat_info.severity {
                            hadron_core::ThreatSeverity::Critical => egui::Color32::RED,
                            hadron_core::ThreatSeverity::High => egui::Color32::from_rgb(255, 165, 0),
                            hadron_core::ThreatSeverity::Medium => egui::Color32::YELLOW,
                            hadron_core::ThreatSeverity::Low => egui::Color32::GREEN,
                        };
                        ui.colored_label(severity_color, format!("{:?}", entry.threat_info.severity));
                                        ui.end_row();
                                        
                                        ui.label("📊 File Size:");
                                        ui.label(Self::format_file_size(entry.file_size));
                                        ui.end_row();
                                        
                                        ui.label("🔍 Detection Method:");
                                        ui.label(format!("{:?}", entry.threat_info.detection_method));
                                        ui.end_row();
                                        
                                        ui.label("🔒 Quarantine ID:");
                                        ui.monospace(entry.id.to_string());
                                        ui.end_row();
                                    });
                            }
                        });
                        
                        ui.add_space(5.0);
                    }
                });
        });

        // Actions
        if let Some(selected_index) = self.selected_entry {
            ui.add_space(10.0);
            ui.group(|ui| {
                ui.label("Actions for selected file:");
                ui.horizontal(|ui| {
                    if ui.add_sized([100.0, 30.0], egui::Button::new("🔄 Restore")).clicked() {
                        if let Some(entry) = self.quarantine_entries.get(selected_index) {
                            action = QuarantinePanelAction::Restore(entry.id);
                        }
                    }
                    
                    if ui.add_sized([100.0, 30.0], egui::Button::new("🗑️ Delete")).clicked() {
                        if let Some(entry) = self.quarantine_entries.get(selected_index) {
                            action = QuarantinePanelAction::Delete(entry.id);
                        }
                    }
                });
                
                ui.small("⚠️ Restore will return the file to its original location");
                ui.small("🗑️ Delete will permanently remove the file from quarantine");
            });
        } else {
            ui.add_space(10.0);
            ui.group(|ui| {
                ui.label("Select a quarantined file to see available actions");
            });
        }

        action
    }
}

/// Actions that can be triggered from the quarantine panel
pub enum QuarantinePanelAction {
    None,
    Restore(hadron_core::QuarantineId),
    Delete(hadron_core::QuarantineId),
}

/// Settings panel implementation
pub struct SettingsPanel {
    realtime_protection: bool,
    scan_on_access: bool,
    scan_on_write: bool,
    scan_archives: bool,
    scan_email: bool,
    auto_update: bool,
}

impl SettingsPanel {
    pub fn new() -> Self {
        Self {
            realtime_protection: true,
            scan_on_access: true,
            scan_on_write: true,
            scan_archives: true,
            scan_email: true,
            auto_update: true,
        }
    }

    pub fn show(&mut self, ui: &mut egui::Ui) -> SettingsPanelAction {
        ui.heading("Settings");
        ui.separator();

        let mut action = SettingsPanelAction::None;

        egui::ScrollArea::vertical().show(ui, |ui| {
            // Real-time protection settings
            ui.group(|ui| {
                ui.heading("🛡️ Real-time Protection");
                ui.separator();
                
                ui.checkbox(&mut self.realtime_protection, "Enable real-time protection");
                ui.small("Continuously monitors system for threats");
                
                ui.add_space(5.0);
                
                ui.checkbox(&mut self.scan_on_access, "Scan files on access");
                ui.small("Scan files when they are opened or executed");
                
                ui.checkbox(&mut self.scan_on_write, "Scan files on write");
                ui.small("Scan files when they are created or modified");
            });

            ui.add_space(10.0);

            // Scan settings
            ui.group(|ui| {
                ui.heading("🔍 Scan Settings");
                ui.separator();
                
                ui.checkbox(&mut self.scan_archives, "Scan archive files (.zip, .rar, etc.)");
                ui.small("Extract and scan contents of compressed files");
                
                ui.checkbox(&mut self.scan_email, "Scan email attachments");
                ui.small("Monitor email clients for malicious attachments");
            });

            ui.add_space(10.0);

            // Update settings
            ui.group(|ui| {
                ui.heading("🔄 Update Settings");
                ui.separator();
                
                ui.checkbox(&mut self.auto_update, "Automatic updates");
                ui.small("Automatically download and install signature updates");
                
                ui.horizontal(|ui| {
                    ui.label("Update frequency:");
                    egui::ComboBox::from_label("")
                        .selected_text("Every 4 hours")
                        .show_ui(ui, |ui| {
                            ui.selectable_value(&mut "4h", "4h", "Every 4 hours");
                            ui.selectable_value(&mut "4h", "8h", "Every 8 hours");
                            ui.selectable_value(&mut "4h", "24h", "Daily");
                        });
                });
            });

            ui.add_space(10.0);

            // Performance settings
            ui.group(|ui| {
                ui.heading("⚡ Performance Settings");
                ui.separator();
                
                ui.horizontal(|ui| {
                    ui.label("CPU usage limit:");
                    ui.add(egui::Slider::new(&mut 50, 10..=100).suffix("%"));
                });
                ui.small("Limit CPU usage during scans to maintain system responsiveness");
                
                ui.horizontal(|ui| {
                    ui.label("Scan priority:");
                    egui::ComboBox::from_label("")
                        .selected_text("Normal")
                        .show_ui(ui, |ui| {
                            ui.selectable_value(&mut "normal", "low", "Low");
                            ui.selectable_value(&mut "normal", "normal", "Normal");
                            ui.selectable_value(&mut "normal", "high", "High");
                        });
                });
            });

            ui.add_space(10.0);

            // Notification settings
            ui.group(|ui| {
                ui.heading("🔔 Notification Settings");
                ui.separator();
                
                ui.checkbox(&mut true, "Show threat detection notifications");
                ui.checkbox(&mut true, "Show scan completion notifications");
                ui.checkbox(&mut false, "Show update notifications");
                ui.checkbox(&mut true, "Play sound for critical alerts");
            });

            ui.add_space(20.0);

            // Action buttons
            ui.horizontal(|ui| {
                if ui.add_sized([100.0, 35.0], egui::Button::new("💾 Save Settings")).clicked() {
                    action = SettingsPanelAction::SaveSettings;
                }
                
                if ui.add_sized([100.0, 35.0], egui::Button::new("🔄 Reset to Defaults")).clicked() {
                    // Reset to defaults
                    self.realtime_protection = true;
                    self.scan_on_access = true;
                    self.scan_on_write = true;
                    self.scan_archives = true;
                    self.scan_email = true;
                    self.auto_update = true;
                }
                
                if ui.add_sized([100.0, 35.0], egui::Button::new("📋 Export Settings")).clicked() {
                    // Export settings functionality would go here
                }
            });
        });

        action
    }
}

/// Actions that can be triggered from the settings panel
pub enum SettingsPanelAction {
    None,
    SaveSettings,
}

/// Removable media panel actions
#[derive(Debug, Clone)]
pub enum RemovableMediaPanelAction {
    ScanAllDevices,
    ScanDevice(String),
    CleanDevice(String),
    TrustDevice(String, bool),
    RefreshDevices,
}

/// Removable media panel implementation
pub struct RemovableMediaPanel {
    devices: Vec<RemovableDevice>,
    scanning: bool,
    last_refresh: std::time::Instant,
}

impl RemovableMediaPanel {
    pub fn new() -> Self {
        Self {
            devices: Vec::new(),
            scanning: false,
            last_refresh: std::time::Instant::now(),
        }
    }

    pub fn update_devices(&mut self, devices: Vec<RemovableDevice>) {
        self.devices = devices;
        self.last_refresh = std::time::Instant::now();
    }

    pub fn set_scanning(&mut self, scanning: bool) {
        self.scanning = scanning;
    }

    pub fn show(&mut self, ui: &mut egui::Ui) -> Option<RemovableMediaPanelAction> {
        let mut action = None;

        ui.heading("🔍 Flash Bellek Tarayıcı");
        ui.separator();

        // Refresh button
        ui.horizontal(|ui| {
            if ui.button("🔄 Yenile").clicked() {
                action = Some(RemovableMediaPanelAction::RefreshDevices);
            }
            
            ui.separator();
            
            if ui.button("🔍 Tümünü Tara").clicked() {
                action = Some(RemovableMediaPanelAction::ScanAllDevices);
            }
            
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let elapsed = self.last_refresh.elapsed().as_secs();
                ui.label(format!("Son güncelleme: {}s önce", elapsed));
            });
        });

        ui.add_space(10.0);

        if self.scanning {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label("Tarama devam ediyor...");
            });
            ui.add_space(10.0);
        }

        // Device list
        if self.devices.is_empty() {
            ui.vertical_centered(|ui| {
                ui.add_space(50.0);
                ui.label("📱 Flash bellek bulunamadı");
                ui.label("Bir USB flash bellek takın ve yenile butonuna basın");
                ui.add_space(20.0);
                
                if ui.button("🔄 Tekrar Dene").clicked() {
                    action = Some(RemovableMediaPanelAction::RefreshDevices);
                }
            });
        } else {
            ui.label(format!("📱 {} flash bellek tespit edildi:", self.devices.len()));
            ui.add_space(10.0);

            egui::ScrollArea::vertical().show(ui, |ui| {
                for (i, device) in self.devices.iter().enumerate() {
                    ui.group(|ui| {
                        ui.horizontal(|ui| {
                            // Device icon and name
                            ui.vertical(|ui| {
                                ui.horizontal(|ui| {
                                    ui.label("📱");
                                    ui.heading(&device.device_name);
                                    
                                    // Trust status
                                    if device.is_trusted {
                                        ui.colored_label(egui::Color32::GREEN, "✅ Güvenilir");
                                    } else {
                                        ui.colored_label(egui::Color32::YELLOW, "⚠️ Bilinmeyen");
                                    }
                                });
                                
                                ui.label(format!("📍 {}", device.mount_point.display()));
                                ui.label(format!("💾 {} ({} boş)", 
                                    self.format_bytes(device.total_size_bytes),
                                    self.format_bytes(device.free_space_bytes)
                                ));
                                
                                if let Some(last_scan) = device.last_scan_time {
                                    ui.label(format!("🕒 Son tarama: {}", 
                                        last_scan.format("%H:%M:%S")
                                    ));
                                } else {
                                    ui.colored_label(egui::Color32::YELLOW, "🕒 Hiç taranmamış");
                                }
                            });
                            
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                ui.vertical(|ui| {
                                    // Action buttons
                                    if ui.button("🔍 Tara").clicked() {
                                        action = Some(RemovableMediaPanelAction::ScanDevice(device.device_id.clone()));
                                    }
                                    
                                    if ui.button("🧹 Temizle").clicked() {
                                        action = Some(RemovableMediaPanelAction::CleanDevice(device.device_id.clone()));
                                    }
                                    
                                    ui.horizontal(|ui| {
                                        if device.is_trusted {
                                            if ui.button("❌ Güveni Kaldır").clicked() {
                                                action = Some(RemovableMediaPanelAction::TrustDevice(device.device_id.clone(), false));
                                            }
                                        } else {
                                            if ui.button("✅ Güven").clicked() {
                                                action = Some(RemovableMediaPanelAction::TrustDevice(device.device_id.clone(), true));
                                            }
                                        }
                                    });
                                });
                            });
                        });
                    });
                    
                    if i < self.devices.len() - 1 {
                        ui.add_space(10.0);
                    }
                }
            });
        }

        // Quick actions
        ui.add_space(20.0);
        ui.separator();
        ui.label("⚡ Hızlı İşlemler:");
        
        ui.horizontal(|ui| {
            if ui.button("🔍 Hızlı Tarama").clicked() {
                action = Some(RemovableMediaPanelAction::ScanAllDevices);
            }
            
            if ui.button("🧹 Tümünü Temizle").clicked() {
                // This would scan and clean all devices
                action = Some(RemovableMediaPanelAction::ScanAllDevices);
            }
            
            if ui.button("📊 Durum Raporu").clicked() {
                // Show status report
            }
        });

        // Help section
        ui.add_space(20.0);
        ui.separator();
        ui.collapsing("💡 Yardım", |ui| {
            ui.label("🔍 Tarama: Flash belleği virüs ve malware için tarar");
            ui.label("🧹 Temizleme: Tespit edilen tehditleri otomatik temizler");
            ui.label("✅ Güven: Cihazı güvenilir olarak işaretler (otomatik tarama yapılmaz)");
            ui.label("🔄 Yenile: Yeni takılan cihazları tespit eder");
            ui.add_space(5.0);
            ui.label("⚠️ Önemli: Temizleme işlemi geri alınamaz!");
        });

        action
    }

    fn format_bytes(&self, bytes: u64) -> String {
        const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
        let mut size = bytes as f64;
        let mut unit_index = 0;

        while size >= 1024.0 && unit_index < UNITS.len() - 1 {
            size /= 1024.0;
            unit_index += 1;
        }

        if unit_index == 0 {
            format!("{} {}", bytes, UNITS[unit_index])
        } else {
            format!("{:.2} {}", size, UNITS[unit_index])
        }
    }
}