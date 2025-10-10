use hadron_core::{ProcessInfo, ThreadInfo, ImageInfo, ProcessMonitor, MonitorResult};
pub struct ProcessMonitorDriver {
    driver_name: String,
}
impl ProcessMonitorDriver {
    pub fn new(driver_name: String) -> Self {
        Self { driver_name }
    }
    pub fn initialize(&self) -> Result<(), hadron_core::DriverError> {
        Ok(())
    }
    pub fn shutdown(&self) -> Result<(), hadron_core::DriverError> {
        Ok(())
    }
}
impl ProcessMonitor for ProcessMonitorDriver {
    fn on_process_create(&self, process_info: &ProcessInfo) -> MonitorResult {
        MonitorResult::Monitor
    }
    fn on_process_terminate(&self, process_id: u32) -> MonitorResult {
        MonitorResult::Allow
    }
    fn on_thread_create(&self, thread_info: &ThreadInfo) -> MonitorResult {
        MonitorResult::Monitor
    }
    fn on_image_load(&self, image_info: &ImageInfo) -> MonitorResult {
        MonitorResult::Monitor
    }
}