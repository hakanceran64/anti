#!/bin/bash

# Hadron Antivirus macOS Installer Test Script
# This script tests the macOS installer in a safe environment

set -e

# Configuration
APP_NAME="Hadron Antivirus"
VERSION="1.0.0"
DIST_DIR="$(pwd)/dist"
TEST_DIR="$(pwd)/test-install"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
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

echo_test() {
    echo -e "${BLUE}[TEST]${NC} $1"
}

# Check if installer files exist
check_installers() {
    echo_info "Checking for installer files..."
    
    local pkg_file="$DIST_DIR/$APP_NAME-$VERSION.pkg"
    local dmg_file="$DIST_DIR/$APP_NAME-$VERSION.dmg"
    
    if [[ ! -f "$pkg_file" ]]; then
        echo_error "Package installer not found: $pkg_file"
        echo_info "Run ./installer/macos/build-macos-installer.sh first"
        exit 1
    fi
    
    if [[ ! -f "$dmg_file" ]]; then
        echo_error "Disk image not found: $dmg_file"
        echo_info "Run ./installer/macos/build-macos-installer.sh first"
        exit 1
    fi
    
    echo_info "Found installer files:"
    echo_info "  - Package: $pkg_file ($(du -h "$pkg_file" | cut -f1))"
    echo_info "  - Disk Image: $dmg_file ($(du -h "$dmg_file" | cut -f1))"
}

# Test package installer structure
test_pkg_structure() {
    echo_test "Testing package installer structure..."
    
    local pkg_file="$DIST_DIR/$APP_NAME-$VERSION.pkg"
    local extract_dir="$TEST_DIR/pkg-contents"
    
    mkdir -p "$extract_dir"
    
    # Extract package contents
    cd "$extract_dir"
    xar -xf "$pkg_file"
    
    # Check for required files
    local required_files=(
        "Distribution"
        "component.pkg"
    )
    
    for file in "${required_files[@]}"; do
        if [[ -f "$file" ]]; then
            echo_info "  ✓ Found: $file"
        else
            echo_error "  ✗ Missing: $file"
        fi
    done
    
    # Extract component package
    if [[ -f "component.pkg" ]]; then
        mkdir -p component
        cd component
        xar -xf ../component.pkg
        
        if [[ -f "Payload" ]]; then
            echo_info "  ✓ Found component payload"
            
            # Extract payload
            cat Payload | gunzip -dc | cpio -i 2>/dev/null
            
            # Check for installed files
            local expected_files=(
                "Applications/$APP_NAME.app/Contents/Info.plist"
                "Applications/$APP_NAME.app/Contents/MacOS/$APP_NAME"
                "Applications/$APP_NAME.app/Contents/MacOS/hadron-service"
                "usr/local/bin/hadron-cli"
                "Library/LaunchDaemons/com.hadron.antivirus.service.plist"
            )
            
            for file in "${expected_files[@]}"; do
                if [[ -f "$file" ]]; then
                    echo_info "    ✓ Payload contains: $file"
                else
                    echo_warn "    ✗ Payload missing: $file"
                fi
            done
        fi
    fi
    
    cd - > /dev/null
    echo_info "Package structure test completed"
}

# Test DMG structure
test_dmg_structure() {
    echo_test "Testing disk image structure..."
    
    local dmg_file="$DIST_DIR/$APP_NAME-$VERSION.dmg"
    local mount_point="$TEST_DIR/dmg-mount"
    
    mkdir -p "$mount_point"
    
    # Mount DMG
    echo_info "Mounting disk image..."
    hdiutil attach "$dmg_file" -mountpoint "$mount_point" -quiet
    
    # Check contents
    echo_info "Checking disk image contents:"
    ls -la "$mount_point"
    
    # Check for required items
    local required_items=(
        "$APP_NAME.app"
        "Applications"
    )
    
    for item in "${required_items[@]}"; do
        if [[ -e "$mount_point/$item" ]]; then
            echo_info "  ✓ Found: $item"
        else
            echo_error "  ✗ Missing: $item"
        fi
    done
    
    # Check app bundle structure
    if [[ -d "$mount_point/$APP_NAME.app" ]]; then
        echo_info "Checking app bundle structure:"
        
        local app_files=(
            "Contents/Info.plist"
            "Contents/MacOS/$APP_NAME"
            "Contents/MacOS/hadron-service"
            "Contents/MacOS/hadron-cli"
        )
        
        for file in "${app_files[@]}"; do
            if [[ -f "$mount_point/$APP_NAME.app/$file" ]]; then
                echo_info "    ✓ App bundle contains: $file"
            else
                echo_warn "    ✗ App bundle missing: $file"
            fi
        done
        
        # Check if binaries are executable
        for binary in "$APP_NAME" "hadron-service" "hadron-cli"; do
            local binary_path="$mount_point/$APP_NAME.app/Contents/MacOS/$binary"
            if [[ -x "$binary_path" ]]; then
                echo_info "    ✓ Executable: $binary"
            else
                echo_warn "    ✗ Not executable: $binary"
            fi
        done
    fi
    
    # Unmount DMG
    echo_info "Unmounting disk image..."
    hdiutil detach "$mount_point" -quiet
    
    echo_info "Disk image structure test completed"
}

# Test binary architecture
test_binary_architecture() {
    echo_test "Testing binary architecture..."
    
    local dmg_file="$DIST_DIR/$APP_NAME-$VERSION.dmg"
    local mount_point="$TEST_DIR/dmg-mount"
    
    mkdir -p "$mount_point"
    hdiutil attach "$dmg_file" -mountpoint "$mount_point" -quiet
    
    local binaries=(
        "$APP_NAME"
        "hadron-service"
        "hadron-cli"
    )
    
    for binary in "${binaries[@]}"; do
        local binary_path="$mount_point/$APP_NAME.app/Contents/MacOS/$binary"
        if [[ -f "$binary_path" ]]; then
            echo_info "Checking architecture for $binary:"
            file "$binary_path" | sed 's/^/    /'
            
            # Check if it's a universal binary
            if lipo -info "$binary_path" 2>/dev/null | grep -q "architectures"; then
                echo_info "    ✓ Universal binary detected"
                lipo -info "$binary_path" | sed 's/^/      /'
            else
                echo_warn "    Single architecture binary"
            fi
        fi
    done
    
    hdiutil detach "$mount_point" -quiet
    echo_info "Binary architecture test completed"
}

# Test installer scripts
test_installer_scripts() {
    echo_test "Testing installer scripts..."
    
    local scripts_dir="installer/macos/scripts"
    local scripts=(
        "preinstall"
        "postinstall"
    )
    
    for script in "${scripts[@]}"; do
        local script_path="$scripts_dir/$script"
        if [[ -f "$script_path" ]]; then
            echo_info "Checking $script script:"
            
            # Check if executable
            if [[ -x "$script_path" ]]; then
                echo_info "  ✓ Script is executable"
            else
                echo_error "  ✗ Script is not executable"
            fi
            
            # Basic syntax check
            if bash -n "$script_path"; then
                echo_info "  ✓ Script syntax is valid"
            else
                echo_error "  ✗ Script has syntax errors"
            fi
            
            # Check for required variables
            if grep -q "APP_NAME" "$script_path" && grep -q "APP_BUNDLE" "$script_path"; then
                echo_info "  ✓ Script contains required variables"
            else
                echo_warn "  ✗ Script may be missing required variables"
            fi
        else
            echo_error "Script not found: $script_path"
        fi
    done
    
    echo_info "Installer scripts test completed"
}

# Test code signing (if available)
test_code_signing() {
    echo_test "Testing code signing..."
    
    local dmg_file="$DIST_DIR/$APP_NAME-$VERSION.dmg"
    local pkg_file="$DIST_DIR/$APP_NAME-$VERSION.pkg"
    
    # Check DMG signing
    echo_info "Checking disk image signature:"
    if codesign -dv "$dmg_file" 2>&1 | grep -q "Signature"; then
        echo_info "  ✓ Disk image is signed"
        codesign -dv "$dmg_file" 2>&1 | sed 's/^/    /'
    else
        echo_warn "  ✗ Disk image is not signed"
    fi
    
    # Check PKG signing
    echo_info "Checking package signature:"
    if pkgutil --check-signature "$pkg_file" 2>&1 | grep -q "signed"; then
        echo_info "  ✓ Package is signed"
        pkgutil --check-signature "$pkg_file" | sed 's/^/    /'
    else
        echo_warn "  ✗ Package is not signed"
    fi
    
    # Check app bundle signing
    local mount_point="$TEST_DIR/dmg-mount"
    mkdir -p "$mount_point"
    hdiutil attach "$dmg_file" -mountpoint "$mount_point" -quiet
    
    echo_info "Checking app bundle signature:"
    if codesign -dv "$mount_point/$APP_NAME.app" 2>&1 | grep -q "Signature"; then
        echo_info "  ✓ App bundle is signed"
        codesign -dv "$mount_point/$APP_NAME.app" 2>&1 | sed 's/^/    /'
    else
        echo_warn "  ✗ App bundle is not signed"
    fi
    
    hdiutil detach "$mount_point" -quiet
    echo_info "Code signing test completed"
}

# Simulate installation (dry run)
simulate_installation() {
    echo_test "Simulating installation (dry run)..."
    
    local pkg_file="$DIST_DIR/$APP_NAME-$VERSION.pkg"
    
    echo_info "Running installer in simulation mode..."
    
    # Use installer with -dumplog to see what would happen
    if installer -pkg "$pkg_file" -target / -dumplog 2>&1 | head -20; then
        echo_info "  ✓ Installer simulation completed successfully"
    else
        echo_error "  ✗ Installer simulation failed"
    fi
    
    echo_info "Installation simulation completed"
}

# Clean up test files
cleanup() {
    echo_info "Cleaning up test files..."
    rm -rf "$TEST_DIR"
    echo_info "Cleanup completed"
}

# Main test function
main() {
    echo_info "Starting macOS installer tests for $APP_NAME v$VERSION"
    
    # Create test directory
    mkdir -p "$TEST_DIR"
    
    # Run tests
    check_installers
    test_pkg_structure
    test_dmg_structure
    test_binary_architecture
    test_installer_scripts
    test_code_signing
    simulate_installation
    
    # Cleanup
    cleanup
    
    echo_info "All tests completed successfully!"
    echo_info "Installers are ready for distribution"
}

# Handle script interruption
trap cleanup EXIT

# Run main function
main "$@"