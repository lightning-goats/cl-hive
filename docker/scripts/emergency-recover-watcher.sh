#!/bin/bash
# =============================================================================
# emergency.recover inotify watcher
# =============================================================================
# Watches for changes to the emergency.recover file and backs it up immediately.
# Uses inotifywait to detect file modifications in real-time.
#
# This script runs inside the container as a supervisor process.
# =============================================================================

set -euo pipefail

LIGHTNING_DIR="${LIGHTNING_DIR:-/data/lightning/bitcoin}"
NETWORK="${NETWORK:-bitcoin}"
BACKUP_DIR="/backups/emergency"
WATCHED_FILE="$LIGHTNING_DIR/$NETWORK/emergency.recover"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] emergency-watcher: $1"
}

backup_emergency_recover() {
    if [[ -f "$WATCHED_FILE" ]]; then
        local timestamp=$(date +%Y%m%d_%H%M%S)
        local backup_file="$BACKUP_DIR/emergency.recover"
        local versioned_backup="$BACKUP_DIR/emergency.recover.$timestamp"

        # Copy current version with secure permissions
        cp "$WATCHED_FILE" "$backup_file"
        chmod 400 "$backup_file"  # SECURITY: Read-only, owner only

        # Keep a versioned copy (retain last 3)
        cp "$WATCHED_FILE" "$versioned_backup"
        chmod 400 "$versioned_backup"  # SECURITY: Read-only, owner only

        # Cleanup old versions (keep last 3) - use -type f to avoid following symlinks
        find "$BACKUP_DIR" -maxdepth 1 -name 'emergency.recover.*' -type f -printf '%T@ %p\n' 2>/dev/null | \
            sort -rn | tail -n +4 | cut -d' ' -f2- | xargs -r rm -f

        log "Backed up emergency.recover ($(stat -c%s "$backup_file") bytes)"
    else
        log "WARNING: $WATCHED_FILE does not exist"
    fi
}

# Ensure backup directory exists with secure permissions
mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"  # SECURITY: Restrict access to owner only

# Initial backup
log "Starting emergency.recover watcher"
log "Watching: $WATCHED_FILE"
log "Backup dir: $BACKUP_DIR"

# Wait for lightning to create the file if it doesn't exist yet
while [[ ! -f "$WATCHED_FILE" ]]; do
    log "Waiting for $WATCHED_FILE to be created..."
    sleep 10
done

# Initial backup on startup
backup_emergency_recover

# Check if inotifywait is available
if ! command -v inotifywait &>/dev/null; then
    log "ERROR: inotifywait not found. Install inotify-tools package."
    log "Falling back to polling mode (30 second interval)"

    # Polling fallback
    last_checksum=""
    while true; do
        if [[ -f "$WATCHED_FILE" ]]; then
            current_checksum=$(sha256sum "$WATCHED_FILE" | cut -d' ' -f1)
            if [[ "$current_checksum" != "$last_checksum" ]]; then
                log "Change detected (checksum: ${current_checksum:0:16}...)"
                backup_emergency_recover
                last_checksum="$current_checksum"
            fi
        fi
        sleep 30
    done
else
    # inotify mode - efficient, event-driven
    log "Using inotify for real-time monitoring"

    # Watch for modifications, moves, and creation
    inotifywait -m -e modify,move,create --format '%w%f %e' "$(dirname "$WATCHED_FILE")" 2>/dev/null | \
    while read -r file event; do
        if [[ "$file" == "$WATCHED_FILE" ]]; then
            log "Event: $event"
            # Small delay to ensure write is complete
            sleep 1
            backup_emergency_recover
        fi
    done
fi
