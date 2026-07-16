#!/bin/bash
set -euo pipefail
SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
APP_DIR="/opt/cloud-wireguard-panel"
STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP_DIR="$APP_DIR/backups/pre-v10.0.1-$STAMP"
mkdir -p "$BACKUP_DIR"
for item in app.py templates static; do
  if [ -e "$APP_DIR/$item" ]; then cp -a "$APP_DIR/$item" "$BACKUP_DIR/"; fi
done
install -m 0644 "$SRC_DIR/app.py" "$APP_DIR/app.py"
rm -rf "$APP_DIR/templates.new" "$APP_DIR/static.new"
cp -a "$SRC_DIR/templates" "$APP_DIR/templates.new"
cp -a "$SRC_DIR/static" "$APP_DIR/static.new"
rm -rf "$APP_DIR/templates.old" "$APP_DIR/static.old"
[ ! -d "$APP_DIR/templates" ] || mv "$APP_DIR/templates" "$APP_DIR/templates.old"
[ ! -d "$APP_DIR/static" ] || mv "$APP_DIR/static" "$APP_DIR/static.old"
mv "$APP_DIR/templates.new" "$APP_DIR/templates"
mv "$APP_DIR/static.new" "$APP_DIR/static"
python3 -m py_compile "$APP_DIR/app.py"
systemctl restart cloud-wireguard.service
sleep 3
systemctl is-active --quiet cloud-wireguard.service
rm -rf "$APP_DIR/templates.old" "$APP_DIR/static.old"
cp -f "$SRC_DIR/CHANGELOG-v10.0.1.md" "$APP_DIR/CHANGELOG-v10.0.1.md"
echo "Cloud WG Panel v10.0.1 installed successfully."
