# HADRON Antivirus Installer

Bu dizin HADRON Antivirüs için Windows installer (MSI) dosyasını oluşturmak için gerekli dosyaları içerir.

## Gereksinimler

1. **WiX Toolset v3.11 veya üzeri**
   - İndirme linki: https://wixtoolset.org/releases/
   - PATH'e eklenmiş olmalı (candle.exe ve light.exe erişilebilir olmalı)

2. **PowerShell 5.0 veya üzeri**

3. **Rust toolchain**
   - Proje workspace'i build edilmiş olmalı

## Installer Oluşturma

### Otomatik Build (Önerilen)

```powershell
# PowerShell'i Administrator olarak çalıştırın
cd installer
.\build-installer.ps1
```

### Manuel Build

```powershell
# 1. Rust projelerini build edin
cargo build --release --workspace

# 2. WiX ile compile edin
candle.exe -dTargetDir="target\release" -out "installer\output\hadron-installer.wixobj" "installer\hadron-installer.wxs"

# 3. MSI dosyasını oluşturun
light.exe -out "installer\output\HADRON-Antivirus-Setup.msi" "installer\output\hadron-installer.wixobj" -ext WixUIExtension -ext WixFirewallExtension
```

## Installer Özellikleri

- **Tam otomatik kurulum**: Tüm bileşenler otomatik olarak kurulur
- **Windows Service**: HADRON servisi otomatik başlatılır
- **Kernel Drivers**: Minifilter ve process monitor driver'ları kurulur
- **Firewall kuralları**: Gerekli firewall istisnaları eklenir
- **Registry ayarları**: Windows Defender exclusion'ları ve diğer ayarlar
- **Start Menu ve Desktop kısayolları**
- **Otomatik uninstall**: Temiz kaldırma işlemi

## Kurulum Sonrası

Kurulum tamamlandıktan sonra:

1. HADRON Antivirus servisi otomatik başlar
2. Real-time protection aktif hale gelir
3. GUI uygulaması Start Menu'den erişilebilir
4. CLI araçları sistem PATH'inde kullanılabilir

## Sorun Giderme

### WiX Toolset bulunamıyor
```
Error: WiX Toolset not found
```
**Çözüm**: WiX Toolset'i indirip kurun ve PATH'e ekleyin.

### Build hatası
```
Error: Failed to build Rust components
```
**Çözüm**: `cargo build --release --workspace` komutunu manuel çalıştırın.

### Driver kurulum hatası
**Çözüm**: PowerShell'i Administrator olarak çalıştırdığınızdan emin olun.

## Dosya Yapısı

```
installer/
├── hadron-installer.wxs     # WiX kaynak dosyası
├── build-installer.ps1     # Build script
├── assets/                 # Installer görselleri
│   ├── hadron-icon.ico
│   ├── banner.bmp
│   ├── dialog.bmp
│   └── license.rtf
└── output/                 # Build çıktıları
    └── HADRON-Antivirus-Setup.msi
```

## Dağıtım

Oluşturulan `HADRON-Antivirus-Setup.msi` dosyası:
- Dijital olarak imzalanmalı (code signing certificate)
- Antivirus tarayıcılarında test edilmeli
- Windows compatibility test edilmeli (Windows 10/11)