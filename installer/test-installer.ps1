# HADRON Antivirus Installer Test Script
param(
    [string]$MsiPath = "output\HADRON-Antivirus-Setup.msi",
    [switch]$Uninstall,
    [switch]$Quiet
)

Write-Host "HADRON Antivirus Installer Test" -ForegroundColor Green
Write-Host "================================" -ForegroundColor Green

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

if (-not $isAdmin) {
    Write-Error "This script must be run as Administrator"
    Write-Host "Please right-click PowerShell and select 'Run as Administrator'" -ForegroundColor Yellow
    exit 1
}

# Check if MSI file exists
if (-not (Test-Path $MsiPath)) {
    Write-Error "MSI file not found: $MsiPath"
    Write-Host "Please build the installer first using build-installer.ps1" -ForegroundColor Yellow
    exit 1
}

if ($Uninstall) {
    Write-Host "Uninstalling HADRON Antivirus..." -ForegroundColor Yellow
    
    # Find installed product
    $product = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like "*HADRON*" }
    
    if ($product) {
        Write-Host "Found installed product: $($product.Name)" -ForegroundColor Gray
        
        if ($Quiet) {
            $product.Uninstall() | Out-Null
        } else {
            $product.Uninstall()
        }
        
        Write-Host "Uninstallation completed" -ForegroundColor Green
    } else {
        Write-Host "HADRON Antivirus is not installed" -ForegroundColor Yellow
    }
} else {
    Write-Host "Installing HADRON Antivirus..." -ForegroundColor Yellow
    Write-Host "MSI Path: $MsiPath" -ForegroundColor Gray
    
    # Prepare msiexec arguments
    $msiArgs = @("/i", "`"$MsiPath`"")
    
    if ($Quiet) {
        $msiArgs += "/quiet"
    } else {
        $msiArgs += "/passive"
    }
    
    # Add logging
    $logFile = "installer-test-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
    $msiArgs += "/l*v"
    $msiArgs += "`"$logFile`""
    
    Write-Host "Running: msiexec $($msiArgs -join ' ')" -ForegroundColor Gray
    
    # Run installer
    $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $msiArgs -Wait -PassThru
    
    if ($process.ExitCode -eq 0) {
        Write-Host "Installation completed successfully!" -ForegroundColor Green
        
        # Verify installation
        Write-Host "Verifying installation..." -ForegroundColor Yellow
        
        $installPath = "C:\Program Files\HADRON Antivirus"
        if (Test-Path $installPath) {
            Write-Host "✓ Installation directory exists: $installPath" -ForegroundColor Green
            
            # Check for key files
            $keyFiles = @(
                "bin\hadron-service.exe",
                "bin\hadron-gui.exe", 
                "bin\hadron-cli.exe",
                "config\default.toml"
            )
            
            foreach ($file in $keyFiles) {
                $fullPath = Join-Path $installPath $file
                if (Test-Path $fullPath) {
                    Write-Host "✓ Found: $file" -ForegroundColor Green
                } else {
                    Write-Host "✗ Missing: $file" -ForegroundColor Red
                }
            }
            
            # Check Windows service
            $service = Get-Service -Name "HadronAntivirus" -ErrorAction SilentlyContinue
            if ($service) {
                Write-Host "✓ Windows service created: $($service.Status)" -ForegroundColor Green
            } else {
                Write-Host "✗ Windows service not found" -ForegroundColor Red
            }
            
            # Check registry entries
            $regPath = "HKLM:\SOFTWARE\HADRON\Antivirus"
            if (Test-Path $regPath) {
                Write-Host "✓ Registry entries created" -ForegroundColor Green
            } else {
                Write-Host "✗ Registry entries missing" -ForegroundColor Red
            }
            
            # Check Start Menu shortcuts
            $startMenuPath = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\HADRON Antivirus"
            if (Test-Path $startMenuPath) {
                Write-Host "✓ Start Menu shortcuts created" -ForegroundColor Green
            } else {
                Write-Host "✗ Start Menu shortcuts missing" -ForegroundColor Red
            }
            
        } else {
            Write-Host "✗ Installation directory not found" -ForegroundColor Red
        }
        
    } else {
        Write-Host "Installation failed with exit code: $($process.ExitCode)" -ForegroundColor Red
        Write-Host "Check log file: $logFile" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "Test completed. Log file: $logFile" -ForegroundColor Cyan