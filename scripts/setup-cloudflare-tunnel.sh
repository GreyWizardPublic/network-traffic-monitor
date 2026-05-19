#!/usr/bin/env bash
# =============================================================================
# setup-cloudflare-tunnel.sh
#
# Installs cloudflared on Arch Linux and creates a Cloudflare Tunnel that
# forwards:
#       https://<SUBDOMAIN>  →  https://localhost:<NTM_PORT>
#
# Installs cloudflared as a systemd daemon that starts automatically on boot.
#
# Usage:
#   sudo bash setup-cloudflare-tunnel.sh
#
# What this script does:
#   1. Downloads and installs the cloudflared binary
#   2. Creates /etc/cloudflared/ with secure permissions
#   3. Authenticates with Cloudflare (interactive — requires a browser on any
#      device; the script prints the URL and waits)
#   4. Creates the tunnel (idempotent — safe to re-run)
#   5. Writes /etc/cloudflared/config.yml
#   6. Creates the DNS CNAME record in your Cloudflare zone
#   7. Installs, enables, and starts the systemd service
#   8. Cleans up all temporary files from the home directory
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

# ── User-configurable settings ─────────────────────────────────────────────────
# Change these three values if needed before running.
TUNNEL_NAME="ntm-dashboard"
SUBDOMAIN="ntm.happyhomelives.me"
NTM_PORT=8443
# ──────────────────────────────────────────────────────────────────────────────

CONFIG_DIR="/etc/cloudflared"
SERVICE_NAME="cloudflared"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
ORIGINCERT="${CONFIG_DIR}/cert.pem"
# cloudflared writes credentials to ~/.cloudflared/ before we move them
CF_HOME_DIR="${HOME}/.cloudflared"

# ── Colour helpers ─────────────────────────────────────────────────────────────
R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; B='\033[0;34m'; N='\033[0m'
step() { printf "\n${B}──── %s ────${N}\n"     "$*"; }
ok()   { printf "${G}  ✓  %s${N}\n"            "$*"; }
warn() { printf "${Y}  !  %s${N}\n"            "$*"; }
die()  { printf "${R}  ✗  %s${N}\n" "$*" >&2; exit 1; }

# ── 0. Root check ──────────────────────────────────────────────────────────────
[[ $EUID -eq 0 ]] || die "This script must be run as root.  Use: sudo bash $0"

# ── 1. Install cloudflared ─────────────────────────────────────────────────────
step "Step 1/7 — Install cloudflared"

if command -v cloudflared &>/dev/null; then
    CF=$(command -v cloudflared)
    ok "Already installed: $CF  ($(cloudflared --version 2>&1 | head -1))"
else
    case "$(uname -m)" in
        x86_64)  CF_ARCH="amd64" ;;
        aarch64) CF_ARCH="arm64" ;;
        armv7l)  CF_ARCH="arm"   ;;
        *)       die "Unsupported CPU architecture: $(uname -m)" ;;
    esac

    DOWNLOAD_URL="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${CF_ARCH}"
    echo "  Downloading: $DOWNLOAD_URL"
    curl -fsSL --progress-bar "$DOWNLOAD_URL" -o /usr/local/bin/cloudflared
    chmod 755 /usr/local/bin/cloudflared
    CF=/usr/local/bin/cloudflared
    ok "Installed: $("$CF" --version 2>&1 | head -1)"
fi

CF=$(command -v cloudflared)

# ── 2. Config directory ────────────────────────────────────────────────────────
step "Step 2/7 — Prepare config directory"

mkdir -p "$CONFIG_DIR"
chmod 700 "$CONFIG_DIR"
ok "$CONFIG_DIR ready (mode 700)"

# ── 3. Authenticate with Cloudflare ───────────────────────────────────────────
step "Step 3/7 — Authenticate with Cloudflare"

if [[ -f "$ORIGINCERT" ]]; then
    ok "cert.pem already present — skipping login"
else
    printf "\n"
    printf "  ┌─────────────────────────────────────────────────────────────┐\n"
    printf "  │  cloudflared will print a URL below.                        │\n"
    printf "  │  Open it in any browser on any device.                      │\n"
    printf "  │  Log in with your Cloudflare account and select             │\n"
    printf "  │  happyhomelives.me when asked to authorise the zone.        │\n"
    printf "  │  This script will continue automatically afterwards.        │\n"
    printf "  └─────────────────────────────────────────────────────────────┘\n\n"

    "$CF" tunnel login

    # cloudflared writes cert.pem to ~/.cloudflared/cert.pem by default.
    # Move it to our system config directory.
    DEFAULT_CERT="${CF_HOME_DIR}/cert.pem"
    if [[ -f "$DEFAULT_CERT" ]]; then
        mv "$DEFAULT_CERT" "$ORIGINCERT"
        chmod 600 "$ORIGINCERT"
        ok "cert.pem moved to $ORIGINCERT"
    elif [[ -f "$ORIGINCERT" ]]; then
        ok "cert.pem already at $ORIGINCERT"
    else
        die "Authentication failed: cert.pem not found in ${CF_HOME_DIR} or ${CONFIG_DIR}"
    fi
fi

# ── 4. Create tunnel (idempotent) ──────────────────────────────────────────────
step "Step 4/7 — Create tunnel: $TUNNEL_NAME"

# Check if a tunnel with this name already exists.
# cloudflared tunnel list output columns: ID  NAME  CREATED  CONNECTIONS
TUNNEL_ID=$(
    "$CF" tunnel --origincert "$ORIGINCERT" list 2>/dev/null \
    | awk -v name="$TUNNEL_NAME" '$2 == name { print $1; exit }'
)

if [[ -n "$TUNNEL_ID" ]]; then
    ok "Tunnel already exists: $TUNNEL_NAME  (${TUNNEL_ID})"
else
    CREATE_OUT=$("$CF" tunnel --origincert "$ORIGINCERT" create "$TUNNEL_NAME" 2>&1)
    echo "  $CREATE_OUT"
    TUNNEL_ID=$(
        printf '%s\n' "$CREATE_OUT" \
        | grep -oE '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' \
        | head -1
    )
    [[ -n "$TUNNEL_ID" ]] || die "Could not extract tunnel UUID from create output."
    ok "Tunnel created: $TUNNEL_NAME  (${TUNNEL_ID})"
fi

# The credentials JSON is written to ~/.cloudflared/<uuid>.json.
# Move it to the system config directory if not already there.
CREDS_SRC="${CF_HOME_DIR}/${TUNNEL_ID}.json"
CREDS_DEST="${CONFIG_DIR}/${TUNNEL_ID}.json"

if [[ -f "$CREDS_DEST" ]]; then
    ok "Credentials already in $CONFIG_DIR"
elif [[ -f "$CREDS_SRC" ]]; then
    mv "$CREDS_SRC" "$CREDS_DEST"
    chmod 600 "$CREDS_DEST"
    ok "Credentials moved to $CREDS_DEST"
else
    die "Credentials file not found at $CREDS_SRC — tunnel may have been created in a previous run; check $CONFIG_DIR"
fi

# ── 5. Write config.yml ────────────────────────────────────────────────────────
step "Step 5/7 — Write ${CONFIG_DIR}/config.yml"

cat > "${CONFIG_DIR}/config.yml" << EOF
tunnel: ${TUNNEL_ID}
credentials-file: ${CREDS_DEST}
no-autoupdate: true

ingress:
  - hostname: ${SUBDOMAIN}
    service: https://localhost:${NTM_PORT}
    originRequest:
      # noTLSVerify is safe here: the connection is loopback-only.
      # Cloudflare handles the public-facing TLS for ${SUBDOMAIN}.
      noTLSVerify: true
      connectTimeout: 10s
      tlsTimeout: 10s
  - service: http_status:404
EOF

chmod 600 "${CONFIG_DIR}/config.yml"
ok "config.yml written"

# ── 6. Create DNS CNAME record ─────────────────────────────────────────────────
step "Step 6/7 — Create DNS route: $SUBDOMAIN"

DNS_EXIT=0
DNS_OUT=$(
    "$CF" tunnel --origincert "$ORIGINCERT" route dns \
        --overwrite-dns "$TUNNEL_NAME" "$SUBDOMAIN" 2>&1
) || DNS_EXIT=$?

echo "  $DNS_OUT"

if [[ $DNS_EXIT -eq 0 ]] || echo "$DNS_OUT" | grep -qiE "already|added|success|cname"; then
    ok "DNS CNAME configured: ${SUBDOMAIN} → ${TUNNEL_ID}.cfargotunnel.com"
else
    warn "Unexpected output from DNS route command (exit ${DNS_EXIT})"
    warn "Verify the CNAME record manually in your Cloudflare dashboard:"
    warn "  ${SUBDOMAIN}  CNAME  ${TUNNEL_ID}.cfargotunnel.com  (proxied)"
fi

# ── 7. Systemd service ─────────────────────────────────────────────────────────
step "Step 7/7 — Install and start systemd service: $SERVICE_NAME"

cat > "$SERVICE_FILE" << EOF
[Unit]
Description=Cloudflare Tunnel — ${TUNNEL_NAME}
Documentation=https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=${CF} tunnel \\
    --config ${CONFIG_DIR}/config.yml \\
    --no-autoupdate \\
    run ${TUNNEL_NAME}
Restart=on-failure
RestartSec=10
TimeoutStopSec=30
StandardOutput=journal
StandardError=journal
SyslogIdentifier=cloudflared

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable  "$SERVICE_NAME"
systemctl restart "$SERVICE_NAME"

# Wait up to 20 s for the service to become active.
echo "  Waiting for service to start..."
for i in $(seq 1 20); do
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        break
    fi
    sleep 1
done

if systemctl is-active --quiet "$SERVICE_NAME"; then
    ok "Service ${SERVICE_NAME} is active and running"
else
    printf "${R}  ✗  Service did not reach active state within 20 s${N}\n" >&2
    systemctl status "$SERVICE_NAME" --no-pager --lines=20 || true
    die "Check logs:  journalctl -u ${SERVICE_NAME} -n 50"
fi

# ── Cleanup ────────────────────────────────────────────────────────────────────
step "Cleanup — removing temporary files"

# Securely overwrite any leftover cloudflared files in the home directory.
# cert.pem is kept in $CONFIG_DIR for future management commands.
# Note: on SSDs, overwriting is best-effort due to wear levelling.
if [[ -d "$CF_HOME_DIR" ]]; then
    find "$CF_HOME_DIR" -type f | while read -r f; do
        # Overwrite with zeros then remove
        FILE_SIZE=$(wc -c < "$f" 2>/dev/null || echo 0)
        if [[ "$FILE_SIZE" -gt 0 ]]; then
            dd if=/dev/zero of="$f" bs=1 count="$FILE_SIZE" conv=notrunc 2>/dev/null || true
            sync
        fi
        rm -f "$f"
    done
    rmdir "$CF_HOME_DIR" 2>/dev/null || rm -rf "$CF_HOME_DIR"
    ok "Removed ${CF_HOME_DIR}"
else
    ok "Nothing to clean up in ${CF_HOME_DIR}"
fi

# ── Summary ────────────────────────────────────────────────────────────────────
printf "\n${G}══════════════════════════════════════════════════════════${N}\n"
printf "${G}  Setup complete.${N}\n"
printf "${G}══════════════════════════════════════════════════════════${N}\n\n"
printf "  %-20s %s\n" "Tunnel name:"    "$TUNNEL_NAME"
printf "  %-20s %s\n" "Tunnel ID:"      "$TUNNEL_ID"
printf "  %-20s https://%s\n" "Public URL:"  "$SUBDOMAIN"
printf "  %-20s https://localhost:%s\n" "Local target:" "$NTM_PORT"
printf "  %-20s %s\n" "Config dir:"     "$CONFIG_DIR"
printf "  %-20s %s\n" "Systemd unit:"   "$SERVICE_FILE"
printf "\n"
printf "  %-20s sudo systemctl status %s\n"  "Check service:"  "$SERVICE_NAME"
printf "  %-20s sudo journalctl -u %s -f\n"  "Live logs:"      "$SERVICE_NAME"
printf "\n"
printf "${Y}  Test from an external network:  https://%s${N}\n" "$SUBDOMAIN"
printf "${Y}  ntm-server must be running on port %s for content to appear.${N}\n\n" "$NTM_PORT"
printf "  To manage this tunnel in future (add DNS routes, etc.):\n"
printf "    cloudflared tunnel --origincert %s <command>\n\n" "$ORIGINCERT"
