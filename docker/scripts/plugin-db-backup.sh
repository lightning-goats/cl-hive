#!/bin/bash
# =============================================================================
# Plugin Database Backup Script
# =============================================================================
# Performs online backups of cl-hive and cl-revenue-ops databases using
# SQLite's backup API. Safe to run on live databases.
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

# Source databases
HIVE_DB="$DATA_DIR/cl_hive.db"
REVENUE_DB="$DATA_DIR/revenue_ops.db"

# Backup destinations
HIVE_BACKUP="$BACKUP_DIR/cl_hive.db"
REVENUE_BACKUP="$BACKUP_DIR/revenue_ops.db"

# Logging
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"; }
log_success() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [OK] $1"; }
log_error() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $1" >&2; }

# Create backup directory
mkdir -p "$BACKUP_DIR"

backup_database() {
    local source="$1"
    local dest="$2"
    local name="$3"

    if [[ ! -f "$source" ]]; then
        log "Skipping $name - source not found: $source"
        return 0
    fi

    # Use SQLite backup API - safe for live databases
    if sqlite3 "$source" ".backup '$dest'" 2>/dev/null; then
        local size=$(du -h "$dest" 2>/dev/null | cut -f1)
        log_success "$name backed up ($size)"
    else
        log_error "Failed to backup $name"
        return 1
    fi
}

run_backup() {
    log "Starting plugin database backup..."

    backup_database "$HIVE_DB" "$HIVE_BACKUP" "cl-hive"
    backup_database "$REVENUE_DB" "$REVENUE_BACKUP" "cl-revenue-ops"

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
