@echo off
echo Building HADRON Antivirus...

REM Build Rust components
echo Building Rust workspace...
cd ..
cargo build --release --workspace
if %ERRORLEVEL% neq 0 (
    echo Failed to build Rust components
    pause
    exit /b 1
)

REM Create target directory structure
echo Creating target directory...
if not exist "target\release" mkdir "target\release"

REM Copy built executables (if they exist)
echo Copying executables...
if exist "target\release\hadron-service.exe" (
    echo   Found hadron-service.exe
) else (
    echo   Warning: hadron-service.exe not found
)

if exist "target\release\hadron-gui.exe" (
    echo   Found hadron-gui.exe
) else (
    echo   Warning: hadron-gui.exe not found
)

if exist "target\release\hadron-cli.exe" (
    echo   Found hadron-cli.exe
) else (
    echo   Warning: hadron-cli.exe not found
)

echo Build completed!
echo.
echo To create the MSI installer:
echo 1. Install WiX Toolset from https://wixtoolset.org/releases/
echo 2. Run: cd installer
echo 3. Run: candle.exe -dTargetDir="..\target\release" -out "output\hadron-installer.wixobj" "hadron-installer.wxs"
echo 4. Run: light.exe -out "output\HADRON-Antivirus-Setup.msi" "output\hadron-installer.wixobj" -ext WixUIExtension -ext WixFirewallExtension

pause