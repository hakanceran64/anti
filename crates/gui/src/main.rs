use eframe::egui;
use anyhow::Result;

fn main() -> Result<()> {
    env_logger::init();

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([800.0, 600.0])
            .with_title("HADRON Antivirus Control Panel")
            .with_icon(eframe::icon_data::from_png_bytes(&[]).unwrap_or_default()),
        ..Default::default()
    };

    eframe::run_native(
        "HADRON Antivirus",
        options,
        Box::new(|_cc| Box::new(HadronApp::default())),
    ).map_err(|e| anyhow::anyhow!("Failed to run GUI: {}", e))
}

struct HadronApp {
    // App state will be added here
}

impl Default for HadronApp {
    fn default() -> Self {
        Self {}
    }
}

impl eframe::App for HadronApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("HADRON Antivirus Control Panel");
            ui.separator();
            
            ui.label("Welcome to HADRON Antivirus - Advanced Windows Protection");
            ui.label(format!("Version: {}", env!("CARGO_PKG_VERSION")));
            
            ui.separator();
            
            if ui.button("Start Quick Scan").clicked() {
                // TODO: Implement quick scan
            }
            
            if ui.button("Start Full Scan").clicked() {
                // TODO: Implement full scan
            }
            
            ui.separator();
            
            ui.label("Real-time Protection: Active");
            ui.label("Last Update: Today");
            ui.label("Threats Detected: 0");
        });
    }
}