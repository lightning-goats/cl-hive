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

# Create backup directory with secure permissions
mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"  # SECURITY: Restrict access to owner only

# Python backup function using sqlite3 backup API with timeout
backup_with_python() {
    timeout 60 python3 << 'EOF'
import sqlite3
import os
import sys
import signal

# Timeout handler for individual database operations
class TimeoutError(Exception):
    pass

def timeout_handler(signum, frame):
    raise TimeoutError("Database backup timed out")

# Set per-database timeout (30 seconds)
DB_TIMEOUT = 30

data_dir = os.environ.get('DATA_DIR', '/data/lightning/bitcoin/bitcoin')
backup_dir = os.environ.get('BACKUP_DIR', '/backups/plugins')

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
        # Set alarm for timeout
        signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(DB_TIMEOUT)

        # Use SQLite backup API - safe for live databases
        # Connection timeout prevents hanging on locked database
        src_conn = sqlite3.connect(source, timeout=10.0)
        dst_conn = sqlite3.connect(dest, timeout=10.0)
        src_conn.backup(dst_conn)
        dst_conn.close()
        src_conn.close()

        # Cancel alarm
        signal.alarm(0)

        # Set secure permissions on backup
        os.chmod(dest, 0o600)

        size = os.path.getsize(dest)
        size_str = f"{size/1024:.1f}KB" if size < 1024*1024 else f"{size/1024/1024:.1f}MB"
        print(f"[OK] {name} backed up ({size_str})")
    except TimeoutError:
        signal.alarm(0)
        print(f"[ERROR] {name}: backup timed out after {DB_TIMEOUT}s", file=sys.stderr)
    except Exception as e:
        signal.alarm(0)
        print(f"[ERROR] {name}: {e}", file=sys.stderr)
EOF
}

# Export for Python script
export DATA_DIR BACKUP_DIR

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
