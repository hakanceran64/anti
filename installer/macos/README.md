# Hadron Antivirus macOS Installer

This directory contains the macOS installer build system for Hadron Antivirus.

## Overview

The macOS installer creates two distribution formats:
- **Package Installer (.pkg)** - Traditional macOS installer package
- **Disk Image (.dmg)** - Drag-and-drop disk image with app bundle

## Files Structure

```
installer/macos/
├── build-macos-installer.sh    # Main build script
├── test-installer.sh           # Installer testing script
├── scripts/
│   ├── preinstall             # Pre-installation script
│   └── postinstall            # Post-installation script
├── resources/
│   ├── welcome.html           # Installer welcome page
│   ├── conclusion.html        # Installation completion page
│   └── icon.icns             # Application icon (optional)
└── README.md                  # This file
```

## Building the Installer

### Prerequisites

1. **macOS System**: Must be run on macOS 10.15 or later
2. **Xcode Command Line Tools**: Required for `pkgbuild`, `productbuild`, and `hdiutil`
   ```bash
   xcode-select --install
   ```
3. **Rust Toolchain**: For building the application binaries
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```

### Basic Build

To build both .pkg and .dmg installers:

```bash
./installer/macos/build-macos-installer.sh
```

This will:
1. Build Rust binaries for the current architecture
2. Create universal binaries (Intel + Apple Silicon) if possible
3. Create an application bundle
4. Build a .pkg installer
5. Create a .dmg disk image
6. Place both installers in the `dist/` directory

### Universal Binary Build

For universal binaries supporting both Intel and Apple Silicon:

```bash
# Add target architectures
rustup target add x86_64-apple-darwin
rustup target add aarch64-apple-darwin

# Build installer
./installer/macos/build-macos-installer.sh
```

### Code Signing

To sign the installers (requires Apple Developer account):

```bash
# Set your Developer ID
export DEVELOPER_ID_INSTALLER="Developer ID Installer: Your Name (TEAM_ID)"

# Build and sign
./installer/macos/build-macos-installer.sh
```

### Notarization

For notarization (requires Apple ID and app-specific password):

```bash
# Set credentials
export APPLE_ID="your-apple-id@example.com"
export APPLE_ID_PASSWORD="your-app-specific-password"
export TEAM_ID="YOUR_TEAM_ID"

# Build, sign, and notarize
./installer/macos/build-macos-installer.sh
```

## Testing the Installer

Before distribution, test the installer:

```bash
./installer/macos/test-installer.sh
```

This will:
- Verify installer file structure
- Check binary architectures
- Validate installer scripts
- Test code signing status
- Simulate installation process

## Installation Process

### What Gets Installed

The installer places the following files:

- **Application Bundle**: `/Applications/Hadron Antivirus.app`
- **CLI Tool**: `/usr/local/bin/hadron-cli`
- **Background Service**: System daemon for real-time protection
- **Launch Daemon**: `/Library/LaunchDaemons/com.hadron.antivirus.service.plist`
- **Uninstaller**: `/Applications/Uninstall Hadron Antivirus.app`

### Installation Steps

1. **Pre-installation**: Stops existing services and removes old files
2. **File Installation**: Copies application files to system locations
3. **Post-installation**: 
   - Sets proper file permissions
   - Creates application data directories
   - Loads and starts the background service
   - Creates uninstaller
   - Shows security setup instructions

### Required Permissions

After installation, users need to grant:

1. **Full Disk Access**:
   - System Preferences → Security & Privacy → Privacy
   - Select "Full Disk Access"
   - Add Hadron Antivirus.app

2. **System Extension** (if prompted):
   - Allow the system extension when prompted
   - May require system restart

## Distribution

### Package Installer (.pkg)

Best for:
- Enterprise deployment
- Automated installation
- Command-line installation
- System administrator control

Usage:
```bash
# GUI installation
open "Hadron Antivirus-1.0.0.pkg"

# Command-line installation
sudo installer -pkg "Hadron Antivirus-1.0.0.pkg" -target /
```

### Disk Image (.dmg)

Best for:
- Individual user installation
- App Store-like experience
- Manual installation preference

Usage:
1. Double-click the .dmg file
2. Drag Hadron Antivirus.app to Applications folder
3. Launch from Applications folder

## Customization

### Installer Appearance

Edit these files to customize the installer:
- `resources/welcome.html` - Welcome page content
- `resources/conclusion.html` - Completion page content
- `resources/icon.icns` - Application icon

### Installation Behavior

Modify these scripts to change installation behavior:
- `scripts/preinstall` - Pre-installation tasks
- `scripts/postinstall` - Post-installation setup

### Build Configuration

Edit `build-macos-installer.sh` to change:
- Application name and bundle identifier
- Version number
- File locations
- Build options

## Troubleshooting

### Common Issues

1. **"Command not found" errors**:
   - Install Xcode Command Line Tools
   - Ensure Rust is installed and in PATH

2. **Code signing failures**:
   - Verify Developer ID certificate is installed
   - Check certificate name matches DEVELOPER_ID_INSTALLER

3. **Notarization failures**:
   - Verify Apple ID credentials
   - Ensure app-specific password is used (not regular password)
   - Check team ID is correct

4. **Universal binary build fails**:
   - Install target architectures with rustup
   - Ensure all dependencies support both architectures

### Debug Information

To debug installer issues:

```bash
# Check installer logs
tail -f /var/log/install.log

# Test package contents
pkgutil --payload-files "Hadron Antivirus-1.0.0.pkg"

# Verify signatures
codesign -dv "Hadron Antivirus-1.0.0.dmg"
pkgutil --check-signature "Hadron Antivirus-1.0.0.pkg"
```

## Security Considerations

### Code Signing

- Always sign installers for distribution
- Use Developer ID certificates for outside App Store distribution
- Sign all binaries within the app bundle

### Notarization

- Required for macOS 10.15+ compatibility
- Ensures malware scanning by Apple
- Prevents Gatekeeper warnings

### Permissions

- Request minimal necessary permissions
- Explain permission requirements to users
- Provide clear setup instructions

## Maintenance

### Updating the Installer

When updating the application:

1. Update version number in `build-macos-installer.sh`
2. Update version in `resources/welcome.html`
3. Update any new file locations or requirements
4. Test the updated installer thoroughly
5. Update code signing certificates if expired

### Compatibility

- Test on multiple macOS versions
- Verify universal binary compatibility
- Check system extension compatibility
- Validate permission requirements

## Support

For installer-related issues:
- Check the build logs for error messages
- Verify system requirements are met
- Test on a clean macOS installation
- Consult Apple's installer documentation