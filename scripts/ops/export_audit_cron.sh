#!/usr/bin/env bash
# ─── RAPTOR Scheduled Audit Log Export ──────────────────────────────────────
# Exports the audit_log to a timestamped JSONL file and optionally ships it
# to an S3-compatible immutable store.
#
# Usage (standalone):
#   ./scripts/ops/export_audit_cron.sh
#
# Usage (cron — daily at 02:00):
#   0 2 * * * /app/scripts/ops/export_audit_cron.sh >> /var/log/raptor-audit-export.log 2>&1
#
# Required env vars:
#   RAPTOR_DB_PATH          Path to SQLite DB (default: data/raptor.db)
#   AUDIT_EXPORT_DIR        Local directory for exported files (default: data/audit_exports)
#
# Optional env vars (S3 shipping):
#   AUDIT_S3_BUCKET         Target S3 bucket (e.g. my-company-raptor-audit)
#   AUDIT_S3_PREFIX         Key prefix inside bucket (default: audit-logs/)
#   AUDIT_S3_REGION         AWS region (default: us-east-1)
#   AWS_PROFILE             Named AWS profile (optional)
#
# Exit codes:
#   0  Success
#   1  Export failed
#   2  S3 upload failed (export itself succeeded)
# ────────────────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

DB_PATH="${RAPTOR_DB_PATH:-${PROJECT_ROOT}/data/raptor.db}"
EXPORT_DIR="${AUDIT_EXPORT_DIR:-${PROJECT_ROOT}/data/audit_exports}"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
EXPORT_FILE="${EXPORT_DIR}/audit_${TIMESTAMP}.jsonl"

# ── Preflight ────────────────────────────────────────────────────────────────
if [ ! -f "${DB_PATH}" ]; then
  echo "[ERROR] Database not found: ${DB_PATH}" >&2
  exit 1
fi

mkdir -p "${EXPORT_DIR}"

# ── Export ───────────────────────────────────────────────────────────────────
echo "[INFO] Exporting audit log → ${EXPORT_FILE}"

python3 "${SCRIPT_DIR}/export_audit_log.py" \
  --db  "${DB_PATH}" \
  --out "${EXPORT_FILE}"

LINES=$(wc -l < "${EXPORT_FILE}" | tr -d ' ')
echo "[INFO] Exported ${LINES} entries to ${EXPORT_FILE}"

# ── Optional integrity verification ──────────────────────────────────────────
python3 "${SCRIPT_DIR}/verify_audit_chain.py" \
  --db "${DB_PATH}" \
  && echo "[INFO] Audit chain integrity: PASS" \
  || { echo "[WARN] Audit chain verification returned non-zero — review immediately" >&2; }

# ── Optional S3 upload ───────────────────────────────────────────────────────
if [ -n "${AUDIT_S3_BUCKET:-}" ]; then
  S3_PREFIX="${AUDIT_S3_PREFIX:-audit-logs/}"
  REGION="${AUDIT_S3_REGION:-us-east-1}"
  S3_KEY="${S3_PREFIX}$(date -u +%Y/%m/%d)/audit_${TIMESTAMP}.jsonl"
  S3_URI="s3://${AUDIT_S3_BUCKET}/${S3_KEY}"

  echo "[INFO] Uploading to ${S3_URI}"
  aws s3 cp "${EXPORT_FILE}" "${S3_URI}" \
    --region "${REGION}" \
    --sse AES256 \
    --no-progress \
    && echo "[INFO] S3 upload complete: ${S3_URI}" \
    || { echo "[ERROR] S3 upload failed — local copy retained at ${EXPORT_FILE}" >&2; exit 2; }
else
  echo "[INFO] AUDIT_S3_BUCKET not set; skipping S3 upload (local-only export)"
fi

# ── Rotation: keep last 90 local exports ─────────────────────────────────────
KEEP=90
TOTAL=$(find "${EXPORT_DIR}" -maxdepth 1 -name "audit_*.jsonl" | wc -l | tr -d ' ')
if [ "${TOTAL}" -gt "${KEEP}" ]; then
  REMOVE=$(( TOTAL - KEEP ))
  echo "[INFO] Pruning ${REMOVE} old local exports (keeping ${KEEP})"
  find "${EXPORT_DIR}" -maxdepth 1 -name "audit_*.jsonl" \
    | sort \
    | head -n "${REMOVE}" \
    | xargs rm -f
fi

echo "[INFO] Audit export complete at $(date -u +%Y-%m-%dT%H:%M:%SZ)"
