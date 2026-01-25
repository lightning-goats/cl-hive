#!/bin/bash
# Generate a CLN rune with permissions required for the MCP server
#
# Usage:
#   ./generate-mcp-rune.sh [node-name]
#
# This script generates a rune with all permissions needed for:
# - Hive plugin operations (hive-*)
# - Revenue-ops plugin operations (revenue-*)
# - Core CLN queries (getinfo, list*, etc.)
# - Fee management (setchannel)
#
# The rune can be used in nodes.production.json for the MCP server.

set -e

NODE_NAME="${1:-default}"

echo "Generating MCP rune for node: $NODE_NAME"
echo ""

# IMPORTANT: All alternatives must be in a SINGLE inner array to be ORed.
# Multiple inner arrays are ANDed together (all must match).
# Format: [["alt1", "alt2", "alt3"]] means alt1 OR alt2 OR alt3
#
# We use "method/list" to match all list* methods (listnodes, listchannels, etc.)
RESTRICTIONS='[["method^hive-", "method^revenue-", "method=getinfo", "method/list", "method=setchannel", "method=feerates", "method=plugin"]]'

echo "Restrictions (ORed alternatives):"
echo "  - method^hive-      : methods starting with 'hive-'"
echo "  - method^revenue-   : methods starting with 'revenue-'"
echo "  - method=getinfo    : getinfo method"
echo "  - method/list       : methods containing 'list' (listfunds, listnodes, etc.)"
echo "  - method=setchannel : setchannel method"
echo "  - method=feerates   : feerates method"
echo "  - method=plugin     : plugin management"
echo ""

# Check if we can access lightning-cli
if command -v lightning-cli &> /dev/null; then
    echo "Generating rune via lightning-cli..."
    echo ""

    # Generate the rune
    RESULT=$(lightning-cli createrune "restrictions=$RESTRICTIONS" 2>&1) || {
        echo "Error: Failed to create rune"
        echo "$RESULT"
        echo ""
        echo "Make sure lightningd is running and you have access to the socket."
        exit 1
    }

    RUNE=$(echo "$RESULT" | jq -r '.rune')
    UNIQUE_ID=$(echo "$RESULT" | jq -r '.unique_id')

    echo "Success! Generated rune:"
    echo ""
    echo "  Rune: $RUNE"
    echo "  ID:   $UNIQUE_ID"
    echo ""
    echo "Add this to your nodes.production.json:"
    echo ""
    echo "  {"
    echo "    \"name\": \"$NODE_NAME\","
    echo "    \"rest_url\": \"https://your-node:3001\","
    echo "    \"rune\": \"$RUNE\","
    echo "    \"ca_cert\": null"
    echo "  }"
    echo ""
else
    echo "lightning-cli not found. Run this command on your CLN node:"
    echo ""
    echo "  lightning-cli createrune 'restrictions=$RESTRICTIONS'"
    echo ""
    echo "Or via docker:"
    echo ""
    echo "  docker exec <container> lightning-cli createrune 'restrictions=$RESTRICTIONS'"
    echo ""
fi

echo "Methods allowed by this rune:"
echo "  - hive-*:           All hive plugin methods"
echo "  - revenue-*:        All revenue-ops methods"
echo "  - getinfo:          Node identity and status"
echo "  - listfunds:        On-chain and channel balances"
echo "  - listpeerchannels: Channel details"
echo "  - listnodes:        Network graph - node info"
echo "  - listchannels:     Network graph - channel info"
echo "  - listpeers:        Connected peer info"
echo "  - listinvoices:     Invoice queries"
echo "  - listpays:         Payment history"
echo "  - setchannel:       Fee adjustments"
echo "  - feerates:         On-chain fee estimates"
echo "  - plugin:           Plugin management"
