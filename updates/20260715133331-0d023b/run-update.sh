#!/bin/bash
set -u
STATUS_PATH=/opt/cloud-wireguard-panel/updates/status.json
LOG_PATH=/opt/cloud-wireguard-panel/updates/update.log
JOB_ID=20260715133331-0d023b
FILENAME=cloud-wireguard-panel-v10.0.1-updater-v2.zip
write_status() {
  STATE="$1"
  MESSAGE="$2"
  python3 - "$STATUS_PATH" "$STATE" "$MESSAGE" "$JOB_ID" "$FILENAME" <<'PY_STATUS'
import json, os, sys
from datetime import datetime
path, state, message, job_id, filename = sys.argv[1:]
payload = {"state": state, "message": message, "job_id": job_id, "filename": filename, "updated_at": datetime.now().isoformat(timespec="seconds")}
tmp = path + ".tmp"
with open(tmp, "w") as handle:
    json.dump(payload, handle, ensure_ascii=False)
os.rename(tmp, path)
PY_STATUS
}
write_status running "جاري تثبيت التحديث"
cd /opt/cloud-wireguard-panel/updates/20260715133331-0d023b/package/cloud-wireguard-panel-v10.0.1-updater-v2
if bash /opt/cloud-wireguard-panel/updates/20260715133331-0d023b/package/cloud-wireguard-panel-v10.0.1-updater-v2/upgrade-v10.0.1.sh >"$LOG_PATH" 2>&1; then
  write_status success "تم تثبيت التحديث بنجاح"
  exit 0
else
  CODE=$?
  write_status failed "فشل تثبيت التحديث. راجع سجل التحديث"
  exit "$CODE"
fi
