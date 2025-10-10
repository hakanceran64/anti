#!/bin/bash

# Hadron Antivirus macOS Installer Build Script
# This script creates both .pkg and .dmg installers for macOS

set -e

# Configuration
APP_NAME="Hadron Antivirus"
APP_BUNDLE="com.hadron.antivirus"
VERSION="1.0.0"
BUILD_DIR="$(pwd)/build"
DIST_DIR="$(pwd)/dist"
RESOURCES_DIR="$(pwd)/installer/macos/resources"
SCRIPTS_DIR="$(pwd)/installer/macos/scripts"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

echo_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

echo_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running on macOS
if [[ "$OSTYPE" != "darwin"* ]]; then
    echo_error "This script must be run on macOS"
    exit 1
fi

# Check for required tools
check_dependencies() {
    echo_info "Checking dependencies..."
    
    if ! command -v cargo &> /dev/null; then
        echo_error "cargo is required but not installed"
        exit 1
    fi
    
    if ! command -v pkgbuild &> /dev/null; then
        echo_error "pkgbuild is required but not installed (part of Xcode Command Line Tools)"
        exit 1
    fi
    
    if ! command -v productbuild &> /dev/null; then
        echo_error "productbuild is required but not installed (part of Xcode Command Line Tools)"
        exit 1
    fi
    
    if ! command -v hdiutil &> /dev/null; then
        echo_error "hdiutil is required but not installed"
        exit 1
    fi
    
    echo_info "All dependencies found"
}

# Clean previous builds
clean_build() {
    echo_info "Cleaning previous builds..."
    rm -rf "$BUILD_DIR"
    rm -rf "$DIST_DIR"
    mkdir -p "$BUILD_DIR"
    mkdir -p "$DIST_DIR"
}

# Build the Rust binaries
build_binaries() {
    echo_info "Building Rust binaries for macOS..."
    
    # Build for current architecture
    cargo build --release
    
    # Build for universal binary (Intel + Apple Silicon)
    if command -v rustup &> /dev/null; then
        echo_info "Building universal binary..."
        rustup target add x86_64-apple-darwin
        rustup target add aarch64-apple-darwin
        
        cargo build --release --target x86_64-apple-darwin
        cargo build --release --target aarch64-apple-darwin
        
        # Create universal binaries
        mkdir -p "$BUILD_DIR/universal"
        
        for binary in hadron-service hadron-cli hadron-gui; do
            if [[ -f "target/x86_64-apple-darwin/release/$binary" ]] && [[ -f "target/aarch64-apple-darwin/release/$binary" ]]; then
                echo_info "Creating universal binary for $binary"
                lipo -create \
                    "target/x86_64-apple-darwin/release/$binary" \
                    "target/aarch64-apple-darwin/release/$binary" \
                    -output "$BUILD_DIR/universal/$binary"
            else
                echo_warn "Universal binary not available for $binary, using single architecture"
                cp "target/release/$binary" "$BUILD_DIR/universal/$binary" 2>/dev/null || true
            fi
        done
    else
        echo_warn "rustup not found, building for current architecture only"
        mkdir -p "$BUILD_DIR/universal"
        cp target/release/hadron-* "$BUILD_DIR/universal/" 2>/dev/null || true
    fi
}

# Create application bundle structure
create_app_bundle() {
    echo_info "Creating application bundle..."
    
    local app_dir="$BUILD_DIR/$APP_NAME.app"
    local contents_dir="$app_dir/Contents"
    local macos_dir="$contents_dir/MacOS"
    local resources_dir="$contents_dir/Resources"
    
    mkdir -p "$macos_dir"
    mkdir -p "$resources_dir"
    
    # Copy binaries
    cp "$BUILD_DIR/universal/hadron-gui" "$macos_dir/$APP_NAME"
    cp "$BUILD_DIR/universal/hadron-service" "$macos_dir/"
    cp "$BUILD_DIR/universal/hadron-cli" "$macos_dir/"
    
    # Make binaries executable
    chmod +x "$macos_dir"/*
    
    # Create Info.plist
    cat > "$contents_dir/Info.plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>$APP_NAME</string>
    <key>CFBundleIdentifier</key>
    <string>$APP_BUNDLE</string>
    <key>CFBundleName</key>
    <string>$APP_NAME</string>
    <key>CFBundleVersion</key>
    <string>$VERSION</string>
    <key>CFBundleShortVersionString</key>
    <string>$VERSION</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleSignature</key>
    <string>HADR</string>
    <key>LSMinimumSystemVersion</key>
    <string>10.15</string>
    <key>NSHighResolutionCapable</key>
    <true/>
    <key>NSRequiresAquaSystemAppearance</key>
    <false/>
    <key>LSApplicationCategoryType</key>
    <string>public.app-category.utilities</string>
    <key>NSHumanReadableCopyright</key>
    <string>Copyright © 2024 Hadron Security. All rights reserved.</string>
</dict>
</plist>
EOF
    
    # Copy icon if available
    if [[ -f "$RESOURCES_DIR/icon.icns" ]]; then
        cp "$RESOURCES_DIR/icon.icns" "$resources_dir/"
        # Add icon to Info.plist
        /usr/libexec/PlistBuddy -c "Add :CFBundleIconFile string icon.icns" "$contents_dir/Info.plist"
    fi
    
    echo_info "Application bundle created at $app_dir"
}

# Create installer package structure
create_installer_structure() {
    echo_info "Creating installer package structure..."
    
    local payload_dir="$BUILD_DIR/payload"
    local app_dir="$payload_dir/Applications"
    local service_dir="$payload_dir/Library/LaunchDaemons"
    local cli_dir="$payload_dir/usr/local/bin"
    
    mkdir -p "$app_dir"
    mkdir -p "$service_dir"
    mkdir -p "$cli_dir"
    
    # Copy app bundle
    cp -R "$BUILD_DIR/$APP_NAME.app" "$app_dir/"
    
    # Copy CLI tool
    cp "$BUILD_DIR/universal/hadron-cli" "$cli_dir/"
    chmod +x "$cli_dir/hadron-cli"
    
    # Create LaunchDaemon plist for service
    cat > "$service_dir/$APP_BUNDLE.service.plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>$APP_BUNDLE.service</string>
    <key>ProgramArguments</key>
    <array>
        <string>/Applications/$APP_NAME.app/Contents/MacOS/hadron-service</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/hadron-antivirus.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/hadron-antivirus-error.log</string>
</dict>
</plist>
EOF
}

# Build .pkg installer
build_pkg() {
    echo_info "Building .pkg installer..."
    
    local component_pkg="$BUILD_DIR/component.pkg"
    local final_pkg="$DIST_DIR/$APP_NAME-$VERSION.pkg"
    
    # Build component package
    pkgbuild \
        --root "$BUILD_DIR/payload" \
        --identifier "$APP_BUNDLE" \
        --version "$VERSION" \
        --scripts "$SCRIPTS_DIR" \
        "$component_pkg"
    
    # Create distribution XML
    cat > "$BUILD_DIR/distribution.xml" << EOF
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="1">
    <title>$APP_NAME</title>
    <organization>$APP_BUNDLE</organization>
    <domains enable_localSystem="true"/>
    <options customize="never" require-scripts="true" rootVolumeOnly="true"/>
    <choices-outline>
        <line choice="default">
            <line choice="$APP_BUNDLE"/>
        </line>
    </choices-outline>
    <choice id="default"/>
    <choice id="$APP_BUNDLE" visible="false">
        <pkg-ref id="$APP_BUNDLE"/>
    </choice>
    <pkg-ref id="$APP_BUNDLE" version="$VERSION" onConclusion="none">component.pkg</pkg-ref>
</installer-gui-script>
EOF
    
    # Build final package
    productbuild \
        --distribution "$BUILD_DIR/distribution.xml" \
        --package-path "$BUILD_DIR" \
        --resources "$RESOURCES_DIR" \
        "$final_pkg"
    
    echo_info "Package installer created: $final_pkg"
}

# Build .dmg disk image
build_dmg() {
    echo_info "Building .dmg disk image..."
    
    local dmg_dir="$BUILD_DIR/dmg"
    local final_dmg="$DIST_DIR/$APP_NAME-$VERSION.dmg"
    
    mkdir -p "$dmg_dir"
    
    # Copy app bundle to DMG directory
    cp -R "$BUILD_DIR/$APP_NAME.app" "$dmg_dir/"
    
    # Create Applications symlink
    ln -s /Applications "$dmg_dir/Applications"
    
    # Copy additional files
    if [[ -f "README.md" ]]; then
        cp "README.md" "$dmg_dir/ReadMe.txt"
    fi
    
    if [[ -f "installer/assets/license.rtf" ]]; then
        cp "installer/assets/license.rtf" "$dmg_dir/License.rtf"
    fi
    
    # Create DMG
    hdiutil create \
        -volname "$APP_NAME" \
        -srcfolder "$dmg_dir" \
        -ov \
        -format UDZO \
        "$final_dmg"
    
    echo_info "Disk image created: $final_dmg"
}

# Sign the installer (if developer certificate is available)
sign_installer() {
    if [[ -n "${DEVELOPER_ID_INSTALLER:-}" ]]; then
        echo_info "Signing installer with certificate: $DEVELOPER_ID_INSTALLER"
        
        # Sign the .pkg
        if [[ -f "$DIST_DIR/$APP_NAME-$VERSION.pkg" ]]; then
            productsign \
                --sign "$DEVELOPER_ID_INSTALLER" \
                "$DIST_DIR/$APP_NAME-$VERSION.pkg" \
                "$DIST_DIR/$APP_NAME-$VERSION-signed.pkg"
            mv "$DIST_DIR/$APP_NAME-$VERSION-signed.pkg" "$DIST_DIR/$APP_NAME-$VERSION.pkg"
        fi
        
        # Sign the .dmg
        if [[ -f "$DIST_DIR/$APP_NAME-$VERSION.dmg" ]]; then
            codesign \
                --sign "$DEVELOPER_ID_INSTALLER" \
                "$DIST_DIR/$APP_NAME-$VERSION.dmg"
        fi
        
        echo_info "Installers signed successfully"
    else
        echo_warn "No signing certificate specified (set DEVELOPER_ID_INSTALLER environment variable)"
        echo_warn "Installers will not be signed"
    fi
}

# Notarize the installer (if Apple ID credentials are available)
notarize_installer() {
    if [[ -n "${APPLE_ID:-}" ]] && [[ -n "${APPLE_ID_PASSWORD:-}" ]]; then
        echo_info "Notarizing installer..."
        
        # Notarize .pkg
        if [[ -f "$DIST_DIR/$APP_NAME-$VERSION.pkg" ]]; then
            xcrun notarytool submit \
                "$DIST_DIR/$APP_NAME-$VERSION.pkg" \
                --apple-id "$APPLE_ID" \
                --password "$APPLE_ID_PASSWORD" \
                --team-id "${TEAM_ID:-}" \
                --wait
        fi
        
        # Notarize .dmg
        if [[ -f "$DIST_DIR/$APP_NAME-$VERSION.dmg" ]]; then
            xcrun notarytool submit \
                "$DIST_DIR/$APP_NAME-$VERSION.dmg" \
                --apple-id "$APPLE_ID" \
                --password "$APPLE_ID_PASSWORD" \
                --team-id "${TEAM_ID:-}" \
                --wait
        fi
        
        echo_info "Notarization completed"
    else
        echo_warn "No Apple ID credentials specified"
        echo_warn "Installers will not be notarized"
    fi
}

# Main build process
main() {
    echo_info "Starting macOS installer build for $APP_NAME v$VERSION"
    
    check_dependencies
    clean_build
    build_binaries
    create_app_bundle
    create_installer_structure
    build_pkg
    build_dmg
    sign_installer
    notarize_installer
    
    echo_info "Build completed successfully!"
    echo_info "Installers created:"
    echo_info "  - Package: $DIST_DIR/$APP_NAME-$VERSION.pkg"
    echo_info "  - Disk Image: $DIST_DIR/$APP_NAME-$VERSION.dmg"
    
    # Show file sizes
    if [[ -f "$DIST_DIR/$APP_NAME-$VERSION.pkg" ]]; then
        local pkg_size=$(du -h "$DIST_DIR/$APP_NAME-$VERSION.pkg" | cut -f1)
        echo_info "  - Package size: $pkg_size"
    fi
    
    if [[ -f "$DIST_DIR/$APP_NAME-$VERSION.dmg" ]]; then
        local dmg_size=$(du -h "$DIST_DIR/$APP_NAME-$VERSION.dmg" | cut -f1)
        echo_info "  - Disk image size: $dmg_size"
    fi
}

# Run main function
main "$@"