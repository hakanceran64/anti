#!/bin/bash
# Flash Bellek Tarama Scripti

echo "🔍 Flash Bellek Tarayıcı"
echo "======================="

cd crates/cli

# Flash bellekleri listele
echo "📱 Takılı flash bellekler:"
cargo run --bin av-cli -- removable-media list

echo ""
echo "🔍 Tüm flash bellekleri taranıyor..."
cargo run --bin av-cli -- removable-media scan-all

echo ""
echo "✅ Tarama tamamlandı!"