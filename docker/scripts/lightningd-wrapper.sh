#!/bin/bash
# =============================================================================
# lightningd Wrapper Script
# =============================================================================
# Wraps lightningd to ensure graceful shutdown with pre-stop hook.
# This script handles SIGTERM by running pre-stop.sh before stopping.
# =============================================================================

set -euo pipefail

NETWORK="${NETWORK:-bitcoin}"
LIGHTNING_DIR="${LIGHTNING_DIR:-/data/lightning/$NETWORK}"
PRE_STOP_SCRIPT="/usr/local/bin/pre-stop.sh"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [lightningd-wrapper] $1"; }

# PID of lightningd process
LIGHTNINGD_PID=""

# Graceful shutdown handler
shutdown_handler() {
    log "Received shutdown signal"

    # Run pre-stop script if it exists
    if [[ -x "$PRE_STOP_SCRIPT" ]]; then
        log "Running pre-stop hook..."
        "$PRE_STOP_SCRIPT" || log "Pre-stop hook returned non-zero (continuing shutdown)"
    else
        log "Pre-stop script not found, sending SIGTERM to lightningd"
        if [[ -n "$LIGHTNINGD_PID" ]] && kill -0 "$LIGHTNINGD_PID" 2>/dev/null; then
            kill -TERM "$LIGHTNINGD_PID" 2>/dev/null || true
        fi
    fi

    # Wait for lightningd to exit
    if [[ -n "$LIGHTNINGD_PID" ]]; then
        log "Waiting for lightningd (PID $LIGHTNINGD_PID) to exit..."
        wait "$LIGHTNINGD_PID" 2>/dev/null || true
    fi

    log "Shutdown complete"
    exit 0
}

# Trap SIGTERM and SIGINT
trap shutdown_handler SIGTERM SIGINT

log "Starting lightningd..."
log "Lightning dir: $LIGHTNING_DIR"

# Start lightningd in background so we can trap signals
/usr/local/bin/lightningd --lightning-dir="$LIGHTNING_DIR" --conf="$LIGHTNING_DIR/config" &
LIGHTNINGD_PID=$!

log "lightningd started with PID $LIGHTNINGD_PID"

# Wait for lightningd (will be interrupted by signals)
wait "$LIGHTNINGD_PID"
EXIT_CODE=$?

log "lightningd exited with code $EXIT_CODE"
exit $EXIT_CODE
