#!/usr/bin/env bash
set -euo pipefail

BACKUP_DIR=${1:?usage: scripts/ops/restore.sh <backup-dir>}

if [ ! -d "$BACKUP_DIR" ]; then
  echo "Backup directory not found: $BACKUP_DIR" >&2
  exit 2
fi

if [ -f "$BACKUP_DIR/SHA256SUMS" ]; then
  (cd "$BACKUP_DIR" && sha256sum -c SHA256SUMS)
fi

mkdir -p data
if [ -f "$BACKUP_DIR/raptor.db" ]; then
  cp "$BACKUP_DIR/raptor.db" data/raptor.db
fi

if [ -f "$BACKUP_DIR/evidence.tgz" ]; then
  tar -C data -xzf "$BACKUP_DIR/evidence.tgz"
fi

if [ -f "$BACKUP_DIR/intel.tgz" ]; then
  tar -C data -xzf "$BACKUP_DIR/intel.tgz"
fi

echo "Restore staged from $BACKUP_DIR. Start services and verify /api/v1/health/detailed."
