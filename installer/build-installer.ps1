# HADRON Antivirus Installer Build Script
param(
    [string]$Configuration = "Release",
    [string]$Platform = "x64",
    [switch]$Clean
)

Write-Host "Building HADRON Antivirus Installer..." -ForegroundColor Green

# Set paths
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$TargetDir = Join-Path $ProjectRoot "target\$Configuration"
$InstallerDir = Join-Path $ProjectRoot "installer"
$OutputDir = Join-Path $InstallerDir "output"

# Clean previous builds if requested
if ($Clean) {
    Write-Host "Cleaning previous builds..." -ForegroundColor Yellow
    if (Test-Path $OutputDir) {
        Remove-Item $OutputDir -Recurse -Force
    }
    if (Test-Path $TargetDir) {
        Remove-Item $TargetDir -Recurse -Force
    }
}

# Create output directory
if (!(Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

# Build Rust components
Write-Host "Building Rust components..." -ForegroundColor Yellow
Set-Location $ProjectRoot

# Build all workspace members in release mode
cargo build --release --workspace

if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to build Rust components"
    exit 1
}

# Copy built executables to target directory
Write-Host "Copying executables..." -ForegroundColor Yellow
$BinFiles = @(
    "hadron-service.exe",
    "hadron-gui.exe", 
    "hadron-cli.exe"
)

foreach ($file in $BinFiles) {
    $source = Join-Path $ProjectRoot "target\release\$file"
    $dest = Join-Path $TargetDir $file
    
    if (Test-Path $source) {
        Copy-Item $source $dest -Force
        Write-Host "  Copied $file" -ForegroundColor Gray
    } else {
        Write-Warning "  $file not found at $source"
    }
}

# Copy DLL dependencies
Write-Host "Copying DLL dependencies..." -ForegroundColor Yellow
$DllFiles = @(
    "hadron_core.dll"
)

foreach ($file in $DllFiles) {
    $source = Join-Path $ProjectRoot "target\release\$file"
    $dest = Join-Path $TargetDir $file
    
    if (Test-Path $source) {
        Copy-Item $source $dest -Force
        Write-Host "  Copied $file" -ForegroundColor Gray
    }
}

# Create placeholder driver files (these would be built separately with WDK)
Write-Host "Creating placeholder driver files..." -ForegroundColor Yellow
$DriverFiles = @(
    "hadron-minifilter.sys",
    "hadron-process-monitor.sys"
)

foreach ($file in $DriverFiles) {
    $dest = Join-Path $TargetDir $file
    # Create empty placeholder files for now
    New-Item -ItemType File -Path $dest -Force | Out-Null
    Write-Host "  Created placeholder $file" -ForegroundColor Gray
}

# Create signature database placeholder
Write-Host "Creating signature database..." -ForegroundColor Yellow
$sigDbPath = Join-Path $ProjectRoot "config\signatures.db"
if (!(Test-Path $sigDbPath)) {
    # Create a simple placeholder signature database
    @"
# HADRON Signature Database v1.0
# This file contains virus signatures and patterns

rule EICAR_Test_File {
    meta:
        description = "EICAR Anti-Virus Test File"
        author = "HADRON Security"
        date = "2024-01-01"
    strings:
        `$eicar = "X5O!P%@AP[4\PZX54(P^)7CC)7}`$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!`$H+H*"
    condition:
        `$eicar
}

rule Suspicious_PowerShell {
    meta:
        description = "Suspicious PowerShell commands"
        author = "HADRON Security"
    strings:
        `$ps1 = "powershell" nocase
        `$ps2 = "Invoke-Expression" nocase
        `$ps3 = "DownloadString" nocase
    condition:
        `$ps1 and (`$ps2 or `$ps3)
}
"@ | Out-File -FilePath $sigDbPath -Encoding UTF8
}

# Check for WiX Toolset
Write-Host "Checking for WiX Toolset..." -ForegroundColor Yellow
$wixPath = Get-Command "candle.exe" -ErrorAction SilentlyContinue
if (!$wixPath) {
    Write-Error "WiX Toolset not found. Please install WiX Toolset v3.11 or later."
    Write-Host "Download from: https://wixtoolset.org/releases/" -ForegroundColor Cyan
    exit 1
}

# Build MSI installer
Write-Host "Building MSI installer..." -ForegroundColor Yellow
Set-Location $InstallerDir

# Compile WiX source
$wixObj = Join-Path $OutputDir "hadron-installer.wixobj"
$msiFile = Join-Path $OutputDir "HADRON-Antivirus-Setup.msi"

Write-Host "  Running candle.exe..." -ForegroundColor Gray
& candle.exe -dTargetDir="$TargetDir" -out "$wixObj" "hadron-installer.wxs"

if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to compile WiX source"
    exit 1
}

Write-Host "  Running light.exe..." -ForegroundColor Gray
& light.exe -out "$msiFile" "$wixObj" -ext WixUIExtension -ext WixFirewallExtension

if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to link MSI installer"
    exit 1
}

# Create installer assets if they don't exist
Write-Host "Creating installer assets..." -ForegroundColor Yellow
$assetsDir = Join-Path $InstallerDir "assets"
if (!(Test-Path $assetsDir)) {
    New-Item -ItemType Directory -Path $assetsDir -Force | Out-Null
}

# Create placeholder license file
$licenseFile = Join-Path $assetsDir "license.rtf"
if (!(Test-Path $licenseFile)) {
    @"
{\rtf1\ansi\deff0 {\fonttbl {\f0 Times New Roman;}}
\f0\fs24 HADRON ANTIVIRUS SOFTWARE LICENSE AGREEMENT

This software is provided under the following license terms:

1. GRANT OF LICENSE
   Subject to the terms of this Agreement, HADRON Security grants you a non-exclusive license to use this software.

2. RESTRICTIONS
   You may not reverse engineer, decompile, or disassemble the software.

3. DISCLAIMER OF WARRANTIES
   This software is provided "AS IS" without warranty of any kind.

4. LIMITATION OF LIABILITY
   In no event shall HADRON Security be liable for any damages arising from the use of this software.

By installing this software, you agree to these terms.
}
"@ | Out-File -FilePath $licenseFile -Encoding UTF8
}

Write-Host "Installer build completed successfully!" -ForegroundColor Green
Write-Host "MSI file location: $msiFile" -ForegroundColor Cyan
Write-Host ""
Write-Host "To install HADRON Antivirus:" -ForegroundColor Yellow
Write-Host "  1. Run as Administrator: msiexec /i `"$msiFile`"" -ForegroundColor Gray
Write-Host "  2. Or double-click the MSI file and follow the wizard" -ForegroundColor Gray