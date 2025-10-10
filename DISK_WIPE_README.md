# Disk Wipe Özelliği

Bu özellik, çıkarılabilir medya cihazlarını (USB sürücüler, SD kartlar, harici diskler) güvenli bir şekilde temizlemek için geliştirilmiştir.

## Özellikler

### 1. Cihaz Listesi
```bash
hadron-cli disk-wipe list
```
- Tüm çıkarılabilir cihazları listeler
- Cihaz ID'si, adı, mount noktası, boyutu ve dosya sistemi bilgilerini gösterir
- Verbose modda ek detaylar gösterir

### 2. Cihaz Tarama
```bash
hadron-cli disk-wipe scan <device_id>
```
- Belirtilen cihazı malware ve tehditler için tarar
- Bulunan tehditleri detaylı olarak listeler
- Tehdit bulunursa wipe önerisinde bulunur

### 3. Hızlı Temizleme (Quick Wipe)
```bash
hadron-cli disk-wipe quick <device_id> [--force]
```
- Cihazı hızlı bir şekilde temizler
- Sadece dosyaları siler, üzerine yazmaz
- `--force` parametresi onay istemini atlar

### 4. Güvenli Temizleme (Secure Wipe)
```bash
hadron-cli disk-wipe secure <device_id> [--force]
```
- Cihazı güvenli bir şekilde temizler
- 3 geçişli rastgele veri üzerine yazma işlemi yapar
- Askeri standartlarda güvenlik (DoD 5220.22-M)
- Daha yavaş ama daha güvenli

## Güvenlik Özellikleri

### Sistem Koruması
- Sistem disklerini (C:\, /, /usr, vb.) temizlemeyi engeller
- Sadece çıkarılabilir medya cihazlarını hedefler
- CD/DVD gibi salt okunur medyaları reddeder
- Ağ sürücülerini güvenlik nedeniyle reddeder

### Onay Sistemi
- Kritik işlemler için kullanıcı onayı ister
- "YES" yazılması gerekir (büyük/küçük harf duyarlı)
- `--force` parametresi ile onay atlanabilir

### Güvenli Silme
- Ring kütüphanesinin güvenli rastgele sayı üreteci kullanılır
- 3 geçişli üzerine yazma:
  1. Rastgele veri
  2. Rastgele veri
  3. Rastgele veri
- Her geçiş sonrası disk senkronizasyonu

## Kullanım Örnekleri

### Temel Kullanım
```bash
# Cihazları listele
hadron-cli disk-wipe list

# USB sürücüyü tara
hadron-cli disk-wipe scan usb_001

# Hızlı temizleme
hadron-cli disk-wipe quick usb_001

# Güvenli temizleme
hadron-cli disk-wipe secure usb_001
```

### Verbose Mod
```bash
# Detaylı bilgi ile cihaz listesi
hadron-cli --verbose disk-wipe list

# Detaylı tarama sonuçları
hadron-cli --verbose disk-wipe scan usb_001

# Detaylı temizleme işlemi
hadron-cli --verbose disk-wipe secure usb_001
```

### Otomatik Mod
```bash
# Onay istemeden hızlı temizleme
hadron-cli disk-wipe quick usb_001 --force

# Onay istemeden güvenli temizleme
hadron-cli disk-wipe secure usb_001 --force
```

## Teknik Detaylar

### Desteklenen Cihaz Türleri
- USB sürücüler
- SD kartlar
- Harici HDD/SSD'ler
- Diğer çıkarılabilir medya

### Desteklenen Dosya Sistemleri
- FAT32
- NTFS
- exFAT
- HFS+
- ext4
- Diğer yaygın dosya sistemleri

### Platform Desteği
- Windows (PowerShell ile cihaz tespiti)
- macOS (diskutil ve /Volumes ile)
- Linux (/proc/mounts ve /media, /mnt ile)

### Performans
- Hızlı temizleme: ~1,000 dosya/saniye
- Güvenli temizleme: ~200 dosya/saniye (3 geçiş nedeniyle)
- 64KB chunk'lar halinde işlem
- Asenkron I/O kullanımı

## Güvenlik Uyarıları

⚠️ **DİKKAT**: Bu işlem geri alınamaz!
- Temizlenen veriler kalıcı olarak silinir
- Güvenli temizleme sonrası veri kurtarma imkansızdır
- İşlem öncesi önemli verileri yedekleyin

⚠️ **Sistem Güvenliği**:
- Sadece çıkarılabilir cihazlarda çalışır
- Sistem disklerini korur
- Yönetici yetkisi gerekebilir

## Hata Durumları

### Yaygın Hatalar
- `Device not found`: Cihaz ID'si bulunamadı
- `Permission denied`: Yetkisiz erişim
- `Device busy`: Cihaz kullanımda
- `Not a removable device`: Sistem diski koruması

### Çözümler
- Cihazın bağlı olduğundan emin olun
- Yönetici yetkisiyle çalıştırın
- Cihazı kullanan programları kapatın
- Cihazı güvenli çıkarma yapın ve tekrar bağlayın

## Örnek Çıktılar

### Cihaz Listesi
```
=== Removable Devices ===
Found 2 removable device(s):

Device ID: usb_001
  Name: USB Drive (Kingston)
  Mount Point: /Volumes/USB_DRIVE
  Size: 8.0 GB
  File System: FAT32

Device ID: sd_001
  Name: SD Card
  Mount Point: /Volumes/SD_CARD
  Size: 32.0 GB
  File System: exFAT
```

### Tarama Sonucu
```
=== Device Security Scan ===
Scanning device: USB Drive (Kingston)
Files Scanned: 1247
✅ No threats detected
Device appears to be clean and safe to use.
Scan Duration: 3.2 seconds
```

### Güvenli Temizleme
```
=== Disk Wipe Operation ===
Device: USB Drive (Kingston)
Files Deleted: 1247
Duration: 156.8 seconds
Secure Overwrite: 3 passes completed
✅ Device successfully wiped!
```

Bu özellik, özellikle güvenlik açısından hassas ortamlarda çıkarılabilir medyaların güvenli bir şekilde temizlenmesi için tasarlanmıştır.