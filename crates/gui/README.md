# Windows Antivirus GUI

This is the graphical user interface for the Windows Antivirus program, built using the egui framework in Rust.

## Features

### ✅ Implemented (Task 12)

1. **GUI Framework Integration**
   - Uses egui as the cross-platform GUI framework
   - Native-like Windows appearance and behavior
   - Responsive and modern interface design

2. **Main Window and Panels**
   - **Dashboard Panel**: System status overview, protection status, scan statistics
   - **Scan Panel**: Quick scan, full scan, custom scan options with progress tracking
   - **Quarantine Panel**: View, restore, and delete quarantined files
   - **Settings Panel**: Configure real-time protection, scan settings, updates, and performance
   - **Notifications Panel**: View and manage system notifications

3. **Real-time Service Communication**
   - Asynchronous communication with the antivirus service
   - Background status updates and scan progress monitoring
   - Event-driven architecture with channels for thread communication
   - Mock API client for testing when service is unavailable

4. **Threat Notification System**
   - Toast notifications for critical threats and events
   - Notification panel with severity indicators
   - Auto-dismissing notifications for non-critical events
   - Sound alerts for critical threats (configurable)

## Architecture

### Components

- **AntivirusApp**: Main application struct managing all panels and state
- **Panels**: Modular UI components (Dashboard, Scan, Quarantine, Settings)
- **NotificationManager**: Handles all notification display and management
- **MockApiClient**: Testing interface when service is unavailable

### Communication

- **Channels**: Used for thread-safe communication between GUI and service
- **Async Operations**: Non-blocking service calls to maintain UI responsiveness
- **Event System**: Real-time updates for scan progress and system status

## User Interface

### Menu Bar
- **File**: Exit application
- **Scan**: Quick scan, Full scan options
- **Tools**: Testing utilities (simulate threats, scan completion)
- **View**: Refresh data, Settings
- **Help**: About dialog

### Navigation Panel
- Dashboard: System overview
- Scan: Scanning operations
- Quarantine: Quarantine management
- Settings: Configuration options
- Notifications: Notification center

### Status Bar
- Current operation status
- Notification count indicator
- Service connection status

## Requirements Fulfilled

### Requirement 10.1: User-Friendly Interface
✅ **WHEN GUI başlatıldığında THEN kullanıcı dostu arayüz görüntülenmeli**
- Clean, intuitive interface with clear navigation
- Modern design with appropriate icons and colors
- Responsive layout that adapts to window size
- Accessibility considerations with proper contrast and sizing

### Requirement 10.4: User Notifications
✅ **WHEN kullanıcı bildirimi gerektiğinde THEN sistem uygun uyarı göstermeli**
- Toast notifications for immediate alerts
- Notification panel for historical view
- Severity-based color coding and icons
- Auto-dismiss for non-critical notifications
- Persistent notifications for threats and errors

## Technical Details

### Dependencies
- **eframe/egui**: Cross-platform GUI framework
- **tokio**: Async runtime for service communication
- **chrono**: Date/time handling for notifications
- **uuid**: Unique identifiers for scans and notifications
- **serde**: Serialization for configuration and data exchange

### Performance
- Non-blocking UI updates
- Efficient rendering with egui's immediate mode
- Background thread communication
- Minimal memory footprint

### Testing
- Mock API client for standalone testing
- Simulation tools for threat detection and scan completion
- Comprehensive error handling and recovery

## Usage

### Running the GUI
```bash
cargo run --package av-gui
```

### Testing Features
- Use "Tools" menu to simulate threat detection
- Use "Tools" menu to simulate scan completion
- All panels are functional with mock data when service is unavailable

## Future Enhancements

- Integration with Windows notification system
- Keyboard shortcuts and accessibility improvements
- Themes and customization options
- Advanced filtering and search in quarantine
- Detailed scan reports and history
- System tray integration
- Multi-language support (requirement 10.5)

## Development Notes

The GUI is designed to be modular and extensible. Each panel is a separate component that can be developed and tested independently. The notification system is comprehensive and handles all types of user alerts as required by the specifications.

The mock API client allows for full GUI testing without requiring the service to be running, making development and testing more efficient.