#!/bin/bash
# Flash Bellek Temizleme Scripti

echo "🧹 Flash Bellek Temizleyici"
echo "=========================="

if [ -z "$1" ]; then
    echo "❌ Kullanım: ./clean-flash.sh '/Volumes/FLASH_ADI'"
    echo "📱 Mevcut flash bellekler:"
    ls /Volumes/ | grep -v "Macintosh HD"
    exit 1
fi

FLASH_PATH="$1"

echo "🔍 Flash bellek taranıyor: $FLASH_PATH"
cd crates/cli

# Önce tara
cargo run --bin av-cli -- scan --scan-type custom --wait "$FLASH_PATH"

echo ""
echo "🧹 Otomatik temizleme başlatılıyor..."

# Otomatik temizle
cargo run --bin av-cli -- scan --scan-type custom --wait --auto-clean --force "$FLASH_PATH"

echo ""
echo "🔍 Son kontrol..."

# Son tarama
cargo run --bin av-cli -- scan --scan-type custom --wait "$FLASH_PATH"

echo ""
echo "✅ Flash bellek temizlendi!"