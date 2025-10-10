# HADRON Antivirus Deployment Guide

Bu dokuman HADRON Antivirüs'ün Windows sistemlerde dağıtımı için gerekli adımları açıklar.

## Gereksinimler

### Geliştirme Ortamı
- Windows 10/11 (64-bit)
- Rust 1.70+
- WiX Toolset v3.11+
- PowerShell 5.0+
- Visual Studio Build Tools
- Windows SDK

### Hedef Sistemler
- Windows 10 version 1909 veya üzeri
- Windows 11 (tüm versiyonlar)
- Windows Server 2019/2022
- 64-bit işlemci (x64)
- Minimum 4 GB RAM
- 2 GB boş disk alanı

## Build Süreci

### 1. Kaynak Kod Hazırlığı

```bash
# Repository'yi klonlayın
git clone https://github.com/hadron-security/hadron-antivirus.git
cd hadron-antivirus

# Dependencies'leri kontrol edin
cargo check --workspace
```

### 2. Release Build

```bash
# Release modunda build
cargo build --release --workspace

# Test çalıştırın
cargo test --workspace --release
```

### 3. Installer Oluşturma

```powershell
# PowerShell'i Administrator olarak çalıştırın
cd installer

# Asset'leri oluşturun (ilk kez)
.\create-assets.ps1

# Installer'ı build edin
.\build-installer.ps1

# Test edin
.\test-installer.ps1
```

## Installer Özellikleri

### Kurulum Bileşenleri

1. **Ana Uygulama**
   - `hadron-service.exe` - Windows servisi
   - `hadron-gui.exe` - Kullanıcı arayüzü
   - `hadron-cli.exe` - Komut satırı araçları
   - `hadron_core.dll` - Core kütüphane

2. **Kernel Drivers**
   - `hadron-minifilter.sys` - Dosya sistemi filtresi
   - `hadron-process-monitor.sys` - Süreç izleme

3. **Konfigürasyon**
   - `default.toml` - Varsayılan ayarlar
   - `signatures.db` - Virüs imzaları

4. **Sistem Entegrasyonu**
   - Windows servisi kaydı
   - Registry ayarları
   - Firewall kuralları
   - Start Menu kısayolları

### Kurulum Dizini Yapısı

```
C:\Program Files\HADRON Antivirus\
├── bin\
│   ├── hadron-service.exe
│   ├── hadron-gui.exe
│   ├── hadron-cli.exe
│   └── hadron_core.dll
├── config\
│   ├── default.toml
│   └── signatures.db
├── drivers\
│   ├── hadron-minifilter.sys
│   └── hadron-process-monitor.sys
├── logs\
└── quarantine\
```

## Dağıtım Stratejileri

### 1. Manuel Dağıtım

**Tek Sistem Kurulumu:**
```cmd
msiexec /i "HADRON-Antivirus-Setup.msi" /quiet /l*v install.log
```

**Ağ Paylaşımından:**
```cmd
msiexec /i "\\server\share\HADRON-Antivirus-Setup.msi" /quiet
```

### 2. Group Policy Dağıtımı

1. **GPO Oluşturma:**
   - Group Policy Management Console açın
   - Yeni GPO oluşturun: "HADRON Antivirus Deployment"

2. **Software Installation:**
   - Computer Configuration → Policies → Software Settings → Software Installation
   - New → Package → HADRON-Antivirus-Setup.msi seçin
   - Deployment Method: "Assigned"

3. **GPO Bağlama:**
   - Hedef OU'ya GPO'yu bağlayın
   - `gpupdate /force` ile test edin

### 3. SCCM/ConfigMgr Dağıtımı

1. **Application Oluşturma:**
   - Software Library → Applications → Create Application
   - MSI dosyasını import edin

2. **Deployment Type:**
   - Installation Program: `msiexec /i "HADRON-Antivirus-Setup.msi" /quiet`
   - Uninstall Program: `msiexec /x {ProductCode} /quiet`

3. **Requirements:**
   - Operating System: Windows 10/11 x64
   - Disk Space: 2 GB
   - RAM: 4 GB

4. **Detection Method:**
   - Registry: `HKLM\SOFTWARE\HADRON\Antivirus\InstallPath`
   - File System: `C:\Program Files\HADRON Antivirus\bin\hadron-service.exe`

### 4. PowerShell DSC

```powershell
Configuration HadronAntivirusInstall {
    param(
        [string]$MsiPath
    )
    
    Import-DscResource -ModuleName PSDesiredStateConfiguration
    
    Node "localhost" {
        Package HadronAntivirus {
            Name = "HADRON Antivirus"
            Path = $MsiPath
            ProductId = "{GUID-HERE}"
            Ensure = "Present"
        }
        
        Service HadronService {
            Name = "HadronAntivirus"
            State = "Running"
            StartupType = "Automatic"
            DependsOn = "[Package]HadronAntivirus"
        }
    }
}
```

## Güvenlik Konuları

### Code Signing

```powershell
# Executable'ları imzalayın
signtool sign /f certificate.pfx /p password /t http://timestamp.digicert.com hadron-service.exe

# MSI'ı imzalayın
signtool sign /f certificate.pfx /p password /t http://timestamp.digicert.com HADRON-Antivirus-Setup.msi
```

### Driver Signing

```cmd
# Test signing (development)
bcdedit /set testsigning on

# Production signing (WHQL)
# Microsoft Hardware Dev Center üzerinden sertifika alın
```

### Windows Defender Exclusions

```powershell
# PowerShell ile exclusion ekleyin
Add-MpPreference -ExclusionPath "C:\Program Files\HADRON Antivirus"
Add-MpPreference -ExclusionProcess "hadron-service.exe"
Add-MpPreference -ExclusionProcess "hadron-gui.exe"
```

## Sorun Giderme

### Yaygın Kurulum Sorunları

**1. "Access Denied" Hatası**
```
Çözüm: Administrator hakları ile çalıştırın
msiexec /i installer.msi /quiet /l*v install.log
```

**2. Driver Yükleme Hatası**
```
Çözüm: Test signing'i etkinleştirin (development)
bcdedit /set testsigning on
```

**3. Service Başlatma Hatası**
```
Çözüm: Event Viewer'da detayları kontrol edin
eventvwr.msc → Windows Logs → System
```

### Log Analizi

**MSI Log Analizi:**
```powershell
# Hata kodlarını arayın
Select-String -Path "install.log" -Pattern "return value 3"

# Custom action hatalarını bulun
Select-String -Path "install.log" -Pattern "CustomAction"
```

**Service Logs:**
```
Konum: C:\Program Files\HADRON Antivirus\logs\service.log
Format: JSON structured logging
Level: INFO, WARN, ERROR
```

## Kaldırma

### Manuel Kaldırma

```cmd
# MSI ile kaldırma
msiexec /x "HADRON-Antivirus-Setup.msi" /quiet

# Product Code ile kaldırma
msiexec /x {ProductCode} /quiet
```

### Temizlik Script'i

```powershell
# Servis durdur
Stop-Service -Name "HadronAntivirus" -Force

# Registry temizle
Remove-Item -Path "HKLM:\SOFTWARE\HADRON" -Recurse -Force

# Dosyaları sil
Remove-Item -Path "C:\Program Files\HADRON Antivirus" -Recurse -Force

# Start Menu temizle
Remove-Item -Path "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\HADRON Antivirus" -Recurse -Force
```

## Performans Optimizasyonu

### Sistem Kaynakları

- **CPU Kullanımı**: %5-10 (idle), %20-30 (scanning)
- **RAM Kullanımı**: 200-500 MB
- **Disk I/O**: Minimal (real-time protection)

### Tuning Parametreleri

```toml
[scan_settings]
max_file_size_mb = 100        # Büyük dosyalar için limit
scan_timeout_seconds = 30     # Tarama timeout'u
heuristic_level = 2           # 1=düşük, 3=yüksek

[realtime_protection]
scan_network_drives = false   # Ağ sürücülerini devre dışı bırak
```

## Monitoring ve Maintenance

### Health Checks

```powershell
# Service durumu
Get-Service -Name "HadronAntivirus"

# Process durumu
Get-Process -Name "hadron-*"

# Log dosyası boyutu
Get-ChildItem "C:\Program Files\HADRON Antivirus\logs" | Measure-Object -Property Length -Sum
```

### Otomatik Güncellemeler

```toml
[updates]
auto_update_enabled = true
update_frequency_hours = 4
update_server_url = "https://updates.hadron-security.com"
```

---

Bu deployment guide'ı takip ederek HADRON Antivirüs'ü Windows ortamlarında başarıyla dağıtabilirsiniz.