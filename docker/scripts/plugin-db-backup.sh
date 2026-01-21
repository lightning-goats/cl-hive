#!/bin/bash
# =============================================================================
# Plugin Database Backup Script
# =============================================================================
# Performs online backups of cl-hive and cl-revenue-ops databases using
# SQLite's backup API via Python. Safe to run on live databases.
#
# Usage:
#   ./plugin-db-backup.sh              # Run backup
#   ./plugin-db-backup.sh --daemon     # Run continuously (every 5 min)
#
# Configuration (via environment):
#   NETWORK              - Bitcoin network (default: bitcoin)
#   BACKUP_INTERVAL      - Seconds between backups in daemon mode (default: 300)
# =============================================================================

set -euo pipefail

# Configuration
NETWORK="${NETWORK:-bitcoin}"
BACKUP_INTERVAL="${BACKUP_INTERVAL:-300}"
DATA_DIR="/data/lightning/$NETWORK/$NETWORK"
BACKUP_DIR="/backups/plugins"

# Logging
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"; }
log_success() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [OK] $1"; }
log_error() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $1" >&2; }

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Python backup function using sqlite3 backup API
backup_with_python() {
    python3 << EOF
import sqlite3
import os
import sys

data_dir = "$DATA_DIR"
backup_dir = "$BACKUP_DIR"

databases = [
    ("cl_hive.db", "cl-hive"),
    ("revenue_ops.db", "cl-revenue-ops"),
]

for db_file, name in databases:
    source = os.path.join(data_dir, db_file)
    dest = os.path.join(backup_dir, db_file)

    if not os.path.exists(source):
        print(f"[SKIP] {name} - source not found: {source}")
        continue

    try:
        # Use SQLite backup API - safe for live databases
        src_conn = sqlite3.connect(source)
        dst_conn = sqlite3.connect(dest)
        src_conn.backup(dst_conn)
        dst_conn.close()
        src_conn.close()

        size = os.path.getsize(dest)
        size_str = f"{size/1024:.1f}KB" if size < 1024*1024 else f"{size/1024/1024:.1f}MB"
        print(f"[OK] {name} backed up ({size_str})")
    except Exception as e:
        print(f"[ERROR] {name}: {e}", file=sys.stderr)
EOF
}

run_backup() {
    log "Starting plugin database backup..."
    backup_with_python
    log "Backup complete"
}

# Main
case "${1:-}" in
    --daemon)
        log "Starting backup daemon (interval: ${BACKUP_INTERVAL}s)"
        while true; do
            run_backup
            sleep "$BACKUP_INTERVAL"
        done
        ;;
    *)
        run_backup
        ;;
esac
