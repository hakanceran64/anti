#!/bin/bash
# Hızlı Tarama Scripti

echo "⚡ Hızlı Tarama"
echo "=============="

cd crates/cli

echo "🔍 Sistem taraması başlatılıyor..."
cargo run --bin av-cli -- scan --scan-type quick --wait .

echo ""
echo "📱 Flash bellek taraması..."
cargo run --bin av-cli -- removable-media scan-all

echo ""
echo "✅ Hızlı tarama tamamlandı!"