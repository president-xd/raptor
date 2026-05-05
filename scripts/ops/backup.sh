#!/usr/bin/env bash
set -euo pipefail

OUT_DIR=${1:-backups/$(date -u +%Y%m%dT%H%M%SZ)}
mkdir -p "$OUT_DIR"

echo "Creating RAPTOR backup in $OUT_DIR"

if [ -f data/raptor.db ]; then
  sqlite3 data/raptor.db ".backup '$OUT_DIR/raptor.db'"
fi

if [ -d data/evidence ]; then
  tar -C data -czf "$OUT_DIR/evidence.tgz" evidence
fi

if [ -d data/intel ]; then
  tar -C data -czf "$OUT_DIR/intel.tgz" intel
fi

docker compose ps --format json > "$OUT_DIR/docker-compose-services.json" 2>/dev/null || true
sha256sum "$OUT_DIR"/* > "$OUT_DIR/SHA256SUMS" 2>/dev/null || true

echo "Backup complete: $OUT_DIR"
