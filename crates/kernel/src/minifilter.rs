use hadron_core::{CallbackData, FilterResult, FileSystemFilter};
pub struct MiniFilterDriver {
    driver_name: String,
    altitude: String,
}
impl MiniFilterDriver {
    pub fn new(driver_name: String, altitude: String) -> Self {
        Self {
            driver_name,
            altitude,
        }
    }
    pub fn initialize(&self) -> Result<(), hadron_core::DriverError> {
        Ok(())
    }
    pub fn shutdown(&self) -> Result<(), hadron_core::DriverError> {
        Ok(())
    }
}
impl FileSystemFilter for MiniFilterDriver {
    fn pre_create(&self, callback_data: &CallbackData) -> FilterResult {
        FilterResult::Allow
    }
    fn post_create(&self, callback_data: &CallbackData) -> FilterResult {
        FilterResult::Allow
    }
    fn pre_read(&self, callback_data: &CallbackData) -> FilterResult {
        FilterResult::Allow
    }
    fn pre_write(&self, callback_data: &CallbackData) -> FilterResult {
        FilterResult::Allow
    }
    fn pre_delete(&self, callback_data: &CallbackData) -> FilterResult {
        FilterResult::Allow
    }
}