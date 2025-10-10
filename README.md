# HADRON Antivirus

**HADRON** - Windows için gelişmiş antivirüs koruması

## Özellikler

- **Gerçek zamanlı koruma**: Dosya sistemi ve süreç izleme
- **Sandbox analizi**: Şüpheli dosyaların güvenli ortamda analizi
- **Makine öğrenmesi**: Gelişmiş tehdit tespiti
- **E-posta koruması**: MAPI entegrasyonu ile e-posta taraması
- **Ağ izleme**: Kötü amaçlı ağ trafiği tespiti
- **Karantina sistemi**: Güvenli dosya izolasyonu
- **Otomatik güncellemeler**: Virüs tanımları ve motor güncellemeleri

## Sistem Gereksinimleri

### Windows
- **İşletim Sistemi**: Windows 10/11 (64-bit)
- **RAM**: Minimum 4 GB
- **Disk Alanı**: 2 GB boş alan
- **İşlemci**: Intel/AMD 64-bit işlemci
- **Yönetici Hakları**: Kurulum için gerekli

### macOS
- **İşletim Sistemi**: macOS 10.15 (Catalina) veya üzeri
- **RAM**: Minimum 4 GB
- **Disk Alanı**: 100 MB boş alan
- **İşlemci**: Intel 64-bit veya Apple Silicon
- **Yönetici Hakları**: Kurulum için gerekli

## Kurulum

### Windows

#### Otomatik Kurulum (Önerilen)

1. `HADRON-Antivirus-Setup.msi` dosyasını indirin
2. Dosyaya sağ tıklayın ve "Yönetici olarak çalıştır" seçin
3. Kurulum sihirbazını takip edin
4. Kurulum tamamlandıktan sonra sistem yeniden başlatılacak

#### Manuel Kurulum

```powershell
# PowerShell'i Administrator olarak çalıştırın
msiexec /i "HADRON-Antivirus-Setup.msi" /quiet
```

### macOS

#### Package Installer (.pkg)

1. `Hadron Antivirus-1.0.0.pkg` dosyasını indirin
2. Dosyaya çift tıklayın
3. Kurulum sihirbazını takip edin
4. Kurulum sonrası güvenlik izinlerini verin:
   - System Preferences → Security & Privacy → Privacy
   - "Full Disk Access" seçin ve Hadron Antivirus.app'i ekleyin

#### Disk Image (.dmg)

1. `Hadron Antivirus-1.0.0.dmg` dosyasını indirin
2. Dosyaya çift tıklayın
3. Hadron Antivirus.app'i Applications klasörüne sürükleyin
4. Applications klasöründen uygulamayı başlatın

#### Komut Satırından Kurulum

```bash
# Package installer ile
sudo installer -pkg "Hadron Antivirus-1.0.0.pkg" -target /

# Installer build etmek için
./installer/macos/build-macos-installer.sh
```

## Kullanım

### GUI Uygulaması

- **Başlat Menüsü**: HADRON Antivirus → HADRON Antivirus
- **Desktop Kısayolu**: HADRON Antivirus simgesi

### Komut Satırı Araçları

```cmd
# Hızlı tarama
hadron-cli scan --scan-type quick

# Tam sistem taraması
hadron-cli scan --scan-type full

# Belirli klasör taraması
hadron-cli scan --path "C:\Users\Username\Downloads"

# Sistem durumu
hadron-cli status

# Virüs tanımlarını güncelle
hadron-cli update

# Karantina yönetimi
hadron-cli quarantine list
hadron-cli quarantine restore <id>
hadron-cli quarantine delete <id>
```

## Konfigürasyon

Konfigürasyon dosyası: `C:\Program Files\HADRON Antivirus\config\default.toml`

### Temel Ayarlar

```toml
[realtime_protection]
enabled = true
scan_on_access = true
scan_on_write = true

[scan_settings]
max_file_size_mb = 100
heuristic_level = 2
use_machine_learning = true

[quarantine]
max_size_gb = 10
auto_delete_days = 30
```

## Bileşenler

### Core Engine (`hadron-core`)
- Tarama motoru
- Tehdit tespiti
- Sandbox sistemi
- ML sınıflandırma

### Kernel Drivers (`hadron-kernel`)
- Minifilter driver (dosya sistemi izleme)
- Process monitor driver (süreç izleme)

### Service (`hadron-service`)
- Windows servisi
- Gerçek zamanlı koruma
- Ağ izleme
- Güncellemeler

### GUI (`hadron-gui`)
- Kullanıcı arayüzü
- Kontrol paneli
- Tarama yönetimi

### CLI (`hadron-cli`)
- Komut satırı araçları
- Otomasyon desteği
- Batch işlemler

## Geliştirme

### Gereksinimler

- Rust 1.70+
- Windows SDK
- WiX Toolset 3.11+
- Visual Studio Build Tools

### Build

```bash
# Tüm workspace'i build et
cargo build --release --workspace

# Installer oluştur
cd installer
.\build-installer.ps1
```

### Test

```bash
# Unit testler
cargo test --workspace

# Sandbox testleri
cargo test -p hadron-core --test sandbox_integration_tests
```

## Güvenlik

- **Kod imzalama**: Tüm executable'lar dijital olarak imzalanmıştır
- **Kernel driver imzalama**: Microsoft WHQL sertifikası
- **Güvenli güncellemeler**: RSA-2048 imzalı güncellemeler
- **Sandbox izolasyonu**: Güvenli analiz ortamı

## Sorun Giderme

### Yaygın Sorunlar

**Kurulum başarısız oluyor**
- Yönetici hakları ile çalıştırın
- Windows Defender'ı geçici olarak devre dışı bırakın
- Disk alanını kontrol edin

**Gerçek zamanlı koruma çalışmıyor**
- Windows servisi durumunu kontrol edin: `sc query HadronAntivirus`
- Event Viewer'da hata loglarını inceleyin
- Konfigürasyon dosyasını kontrol edin

**Yüksek CPU kullanımı**
- Tarama ayarlarını düşürün
- Heuristic level'ı azaltın
- Exclusion listesi ekleyin

### Log Dosyaları

- **Service Logs**: `C:\Program Files\HADRON Antivirus\logs\service.log`
- **Scan Logs**: `C:\Program Files\HADRON Antivirus\logs\scan.log`
- **Windows Event Log**: Applications and Services Logs → HADRON Antivirus

## Lisans

Bu yazılım özel lisans altında dağıtılmaktadır. Kullanım koşulları için lisans sözleşmesini okuyun.

## Destek

- **Web**: https://hadron-security.com
- **E-posta**: support@hadron-security.com
- **Dokümantasyon**: https://docs.hadron-security.com

---

**HADRON Security** © 2024 - Tüm hakları saklıdır.