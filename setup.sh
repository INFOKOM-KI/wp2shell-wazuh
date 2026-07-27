#!/usr/bin/env bash
# =============================================================================
# WP2Shell Wazuh Detection Rules — One-Command Deployment
# =============================================================================
# Deploys wp2shell decoders and rules to a Wazuh Manager (4.x+).
#
# Usage:
#   sudo bash setup.sh                    # Full deploy + restart
#   sudo bash setup.sh --no-restart       # Deploy only, no service restart
#   sudo bash setup.sh --validate-only    # Syntax-check existing rules
#   sudo bash setup.sh --dry-run          # Show what would be copied
#
# Requires: Wazuh Manager installed at /var/ossec
# =============================================================================
set -euo pipefail

WAZUH_HOME="${WAZUH_HOME:-/var/ossec}"
DECODER_DIR="$WAZUH_HOME/etc/decoders"
RULES_DIR="$WAZUH_HOME/etc/rules"
OSSEC_CONF="$WAZUH_HOME/etc/ossec.conf"
LOG="$WAZUH_HOME/logs/ossec.log"
RESTART=1
VALIDATE_ONLY=0
DRY_RUN=0

RED='\033[31m'; GRN='\033[32m'; YEL='\033[33m'; DIM='\033[2m'; OFF='\033[0m'
say() { echo -e "${GRN}[+]${OFF} $*"; }
warn() { echo -e "${YEL}[!]${OFF} $*"; }
err() { echo -e "${RED}[-]${OFF} $*"; exit 1; }

# Parse args
for arg in "$@"; do
  case "$arg" in
    --no-restart) RESTART=0 ;;
    --validate-only) VALIDATE_ONLY=1 ;;
    --dry-run) DRY_RUN=1 ;;
    -h|--help)
      echo "Usage: sudo bash setup.sh [--no-restart] [--validate-only] [--dry-run]"
      exit 0 ;;
    *) err "Unknown arg: $arg" ;;
  esac
done

# Pre-flight checks
[ "$(id -u)" = "0" ] || err "Must run as root (sudo bash setup.sh)"
[ -d "$WAZUH_HOME" ] || err "Wazuh not found at $WAZUH_HOME"

if [ "$VALIDATE_ONLY" -eq 1 ]; then
  say "Validating existing rules via wazuh-logtest..."
  if [ -x "$WAZUH_HOME/bin/wazuh-logtest" ]; then
    # Feed a known-wp2shell log line and check for rule match
    LOG_LINE='192.168.1.100 - - [27/Jul/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 1234 "-" "wp2shell-rce/1.0"'
    echo "$LOG_LINE" | "$WAZUH_HOME/bin/wazuh-logtest" -v 2>&1 || true
    say "Validation complete."
  else
    warn "wazuh-logtest not found — skipping validation"
  fi
  exit 0
fi

# DRY RUN
if [ "$DRY_RUN" -eq 1 ]; then
  say "DRY RUN — would copy:"
  echo "  wazuh/wp2shell_decoders.xml → $DECODER_DIR/"
  echo "  wazuh/wp2shell_rules.xml    → $RULES_DIR/"
  if grep -q "wp2shell_rules.xml" "$OSSEC_CONF" 2>/dev/null; then
    echo "  (rules already included in ossec.conf)"
  else
    echo "  + add <include>etc/rules/wp2shell_rules.xml</include> to ossec.conf"
  fi
  exit 0
fi

# Deploy decoders
say "Deploying decoders..."
cp wazuh/wp2shell_decoders.xml "$DECODER_DIR/"
chown wazuh:wazuh "$DECODER_DIR/wp2shell_decoders.xml" 2>/dev/null || chown ossec:ossec "$DECODER_DIR/wp2shell_decoders.xml" 2>/dev/null || true
chmod 640 "$DECODER_DIR/wp2shell_decoders.xml"

# Deploy rules
say "Deploying rules..."
cp wazuh/wp2shell_rules.xml "$RULES_DIR/"
chown wazuh:wazuh "$RULES_DIR/wp2shell_rules.xml" 2>/dev/null || chown ossec:ossec "$RULES_DIR/wp2shell_rules.xml" 2>/dev/null || true
chmod 640 "$RULES_DIR/wp2shell_rules.xml"

# Register rules in ossec.conf
if grep -q "wp2shell_rules.xml" "$OSSEC_CONF" 2>/dev/null; then
  warn "wp2shell_rules.xml already included in ossec.conf — skipping"
else
  say "Registering rules in ossec.conf..."
  # Insert before closing </ruleset> tag
  if grep -q '</ruleset>' "$OSSEC_CONF"; then
    sed -i 's|</ruleset>|  <include>etc/rules/wp2shell_rules.xml</include>\n</ruleset>|' "$OSSEC_CONF"
    say "Added <include> to ossec.conf"
  else
    warn "Could not find </ruleset> in ossec.conf — add manually:"
    echo "  <include>etc/rules/wp2shell_rules.xml</include>"
  fi
fi

# Restart
if [ "$RESTART" -eq 1 ]; then
  say "Restarting Wazuh Manager..."
  if systemctl is-active --quiet wazuh-manager 2>/dev/null; then
    systemctl restart wazuh-manager
  elif systemctl is-active --quiet wazuh-server 2>/dev/null; then
    systemctl restart wazuh-server
  elif [ -x "$WAZUH_HOME/bin/wazuh-control" ]; then
    "$WAZUH_HOME/bin/wazuh-control" restart
  else
    warn "Could not restart — do it manually"
  fi
  say "Done. Check alerts: tail -f $WAZUH_HOME/logs/alerts/alerts.json | grep wp2shell"
else
  say "Deployed. Restart Wazuh Manager to activate rules."
fi
