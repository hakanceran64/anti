# HADRON Antivirus Asset Creation Script
Write-Host "Creating installer assets for HADRON Antivirus..." -ForegroundColor Green

$AssetsDir = "assets"
if (!(Test-Path $AssetsDir)) {
    New-Item -ItemType Directory -Path $AssetsDir -Force | Out-Null
}

# Create a simple text-based icon file (placeholder)
Write-Host "Creating icon file..." -ForegroundColor Yellow
$iconContent = @"
This is a placeholder for the HADRON Antivirus icon.
In a real implementation, this would be a proper .ico file
with multiple resolutions (16x16, 32x32, 48x48, 256x256).

The icon should represent:
- Security/Shield theme
- Modern, professional look
- HADRON branding colors
- Windows-compatible format
"@

$iconContent | Out-File -FilePath "$AssetsDir\hadron-icon.ico.txt" -Encoding UTF8

# Create banner image placeholder
Write-Host "Creating banner image..." -ForegroundColor Yellow
$bannerContent = @"
HADRON Antivirus Installer Banner
==================================

This is a placeholder for the installer banner image.
Dimensions: 493 x 58 pixels
Format: BMP
Colors: Professional blue/white theme

Should include:
- HADRON logo
- "Advanced Windows Protection" tagline
- Clean, modern design
"@

$bannerContent | Out-File -FilePath "$AssetsDir\banner.bmp.txt" -Encoding UTF8

# Create dialog image placeholder
Write-Host "Creating dialog image..." -ForegroundColor Yellow
$dialogContent = @"
HADRON Antivirus Dialog Image
=============================

This is a placeholder for the installer dialog image.
Dimensions: 493 x 312 pixels
Format: BMP
Colors: Professional theme matching banner

Should include:
- HADRON branding
- Security-themed graphics
- Professional appearance
- Windows installer style
"@

$dialogContent | Out-File -FilePath "$AssetsDir\dialog.bmp.txt" -Encoding UTF8

Write-Host "Asset placeholders created successfully!" -ForegroundColor Green
Write-Host ""
Write-Host "To complete the installer, you need to:" -ForegroundColor Yellow
Write-Host "1. Replace .txt files with actual image files:" -ForegroundColor Gray
Write-Host "   - hadron-icon.ico (Windows icon format)" -ForegroundColor Gray
Write-Host "   - banner.bmp (493x58 BMP image)" -ForegroundColor Gray
Write-Host "   - dialog.bmp (493x312 BMP image)" -ForegroundColor Gray
Write-Host "2. Ensure license.rtf is properly formatted" -ForegroundColor Gray
Write-Host "3. Test the installer on a clean Windows system" -ForegroundColor Gray