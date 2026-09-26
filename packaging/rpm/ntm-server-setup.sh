#!/usr/bin/env bash
# ntm-server-setup.sh — first-time configuration of an RPM-installed ntm-server
# that sits behind a Cloudflare Tunnel on the same host.
#
# Run as root AFTER `dnf install ntm-server`:
#
#   sudo packaging/rpm/ntm-server-setup.sh \
#       --host ntm.happyhomelives.me \
#       --siwa-service-id <Apple Services ID> \
#       --admin-email <your Apple ID email>            # or --admin-sub <Apple user id>
#       [--client-pubkey <64-hex> --client-name <label>]
#       [--domain-assoc <apple-developer-domain-association.txt>]
#       [--port 8443]
#
# Idempotent: an existing file is NEVER overwritten (delete it to regenerate).
# It does not start the service; the last lines print the commands to do so.
#
# Creates under /etc/ntm-server (owned by ntm-server):
#   server_cert.pem / server_key.pem  self-signed origin cert (cloudflared uses
#                                     noTLSVerify on loopback; the public cert
#                                     is Cloudflare's)
#   allowed_clients.txt               >= 1 client key is MANDATORY. Without
#                                     --client-pubkey, an Ed25519 identity is
#                                     generated for THIS host's future ntm-client
#                                     at /root/ntm-client-identity.pem
#   ntm-server.conf                   unified port on 127.0.0.1, WebAuthn,
#                                     Sign in with Apple, update_dir, IP DB
# and /var/lib/ntm-server/updates (client auto-update distribution).
#
# Why Sign in with Apple is needed: passkey registration is admin-only, and the
# FIRST admin session can only come from Sign in with Apple (api-protocol.md
# §3b). Without --siwa-service-id the server runs, but nobody can log in.

set -euo pipefail

HOST=ntm.happyhomelives.me
PORT=8443
SIWA_ID=""; ADMIN_EMAIL=""; ADMIN_SUB=""
IOS_BUNDLE=com.ntm.NTMDashboard
ASSOC=""; CLIENT_PUB=""; CLIENT_NAME=""

die()  { echo "ERROR [ntm-server-setup]: $*" >&2; exit 1; }
ok()   { echo "  ✓ $*"; }
skip() { echo "  - $* (exists, left unchanged)"; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --host)            HOST="$2"; shift ;;
        --port)            PORT="$2"; shift ;;
        --siwa-service-id) SIWA_ID="$2"; shift ;;
        --admin-email)     ADMIN_EMAIL="$2"; shift ;;
        --admin-sub)       ADMIN_SUB="$2"; shift ;;
        --ios-bundle-id)   IOS_BUNDLE="$2"; shift ;;
        --domain-assoc)    ASSOC="$2"; shift ;;
        --client-pubkey)   CLIENT_PUB="$2"; shift ;;
        --client-name)     CLIENT_NAME="$2"; shift ;;
        -h|--help)         sed -n '2,33p' "$0"; exit 0 ;;
        *) die "unknown option $1 (see --help)" ;;
    esac; shift
done

[[ $EUID -eq 0 ]] || die "run as root (sudo)"
rpm -q ntm-server >/dev/null || die "ntm-server is not installed (dnf install ntm-server)"
getent passwd ntm-server >/dev/null || die "user ntm-server missing (reinstall the package)"
[[ "$HOST" =~ ^[a-z0-9.-]+$ ]] || die "bad --host"
[[ "$PORT" =~ ^[0-9]+$ && $PORT -ge 1 && $PORT -le 65535 ]] || die "bad --port"
[[ -z "$CLIENT_PUB" || "$CLIENT_PUB" =~ ^[0-9a-f]{64}$ ]] || die "--client-pubkey must be 64 lowercase hex"
[[ -z "$ASSOC" || -f "$ASSOC" ]] || die "--domain-assoc file not found: $ASSOC"
if [[ -n "$SIWA_ID" && -z "$ADMIN_EMAIL$ADMIN_SUB" ]]; then
    die "--siwa-service-id needs --admin-email or --admin-sub (who becomes admin)"
fi

E=/etc/ntm-server
L=/var/lib/ntm-server
umask 027
echo "ntm-server setup for https://$HOST (unified port 127.0.0.1:$PORT)"

# 1. TLS origin certificate --------------------------------------------------
if [[ -f $E/server_key.pem || -f $E/server_cert.pem ]]; then
    skip "TLS cert/key"
else
    openssl req -x509 -newkey rsa:3072 -nodes -days 3650 -subj "/CN=$HOST" \
        -addext "subjectAltName=DNS:$HOST,DNS:localhost,IP:127.0.0.1" \
        -keyout $E/server_key.pem -out $E/server_cert.pem 2>/dev/null
    ok "self-signed origin cert for $HOST (10 years): $E/server_cert.pem"
fi

# 2. Client allow-list -----------------------------------------------------
if [[ -s $E/allowed_clients.txt ]]; then
    skip "allowed_clients.txt"
else
    if [[ -z "$CLIENT_PUB" ]]; then
        ID=/root/ntm-client-identity.pem
        if [[ ! -f $ID ]]; then
            (umask 077; openssl genpkey -algorithm ED25519 -out $ID)
            ok "generated an Ed25519 client identity for this host: $ID"
        fi
        CLIENT_PUB=$(openssl pkey -in $ID -pubout -outform DER | tail -c 32 | od -An -v -tx1 | tr -d ' \n')
        CLIENT_NAME="${CLIENT_NAME:-$(uname -n | cut -d. -f1)}"
    fi
    {
        echo "# ntm-server allow-list: <64-hex Ed25519 public key> [nickname]"
        echo "$CLIENT_PUB ${CLIENT_NAME:-client1}"
    } > $E/allowed_clients.txt
    ok "allowed_clients.txt with 1 client (${CLIENT_NAME:-client1})"
fi

# 3. Apple domain association (optional) -----------------------------------
if [[ -n "$ASSOC" ]]; then
    if [[ -f $E/apple-developer-domain-association.txt ]]; then
        skip "apple-developer-domain-association.txt"
    else
        install -m0640 "$ASSOC" $E/apple-developer-domain-association.txt
        ok "Apple domain association file installed"
    fi
fi

# 4. Config ------------------------------------------------------------------
if [[ -f $E/ntm-server.conf ]]; then
    skip "ntm-server.conf"
else
    {
        echo "# ntm-server.conf — generated by ntm-server-setup.sh on $(date -u +%F)."
        echo "# Reference for every key: /usr/share/doc/ntm-server/ntm-server.conf.example"
        echo
        echo "# One TLS port for ntm-client (ALPN ntm-wire) and the dashboard (http/1.1)."
        echo "# Loopback only: all traffic arrives through cloudflared on this host."
        echo "port=$PORT"
        echo "client_bind=127.0.0.1"
        echo "cert=$E/server_cert.pem"
        echo "key=$E/server_key.pem"
        echo "allowed_keys=$E/allowed_clients.txt"
        echo "trusted_proxy=127.0.0.1"
        echo
        echo "# Passkeys (registered from the admin page after the first Apple sign-in)."
        echo "webauthn_rp_id=$HOST"
        echo "webauthn_rp_name=Network Traffic Monitor"
        echo "webauthn_credentials_file=$E/webauthn_credentials.json"
        echo
        if [[ -n "$SIWA_ID" ]]; then
            echo "# Sign in with Apple — how the first admin session is established."
            echo "siwa_service_id=$SIWA_ID"
            echo "siwa_redirect_uri=https://$HOST/auth/apple/callback"
            echo "siwa_ios_bundle_id=$IOS_BUNDLE"
            [[ -n "$ADMIN_EMAIL" ]] && echo "siwa_admins=$ADMIN_EMAIL"
            [[ -n "$ADMIN_SUB" ]] && echo "siwa_admin_subs=$ADMIN_SUB"
            echo "siwa_admin_file=$E/siwa_admins.json"
            [[ -n "$ASSOC" ]] && echo "siwa_domain_assoc_file=$E/apple-developer-domain-association.txt"
        else
            echo "# Sign in with Apple NOT configured: nobody can log in to the dashboard"
            echo "# until siwa_service_id / siwa_redirect_uri / siwa_admins are set."
        fi
        echo
        echo "update_dir=$L/updates"
        echo "aggregation_window_days=7"
        echo "ip_db_path=$L/ip2asn-combined.tsv.gz"
        echo "ip_db_url=https://iptoasn.com/data/ip2asn-combined.tsv.gz"
        echo "ip_db_update_interval_days=7"
        echo "ip_db_auto_update=true"
    } > $E/ntm-server.conf
    ok "ntm-server.conf"
fi

# 5. Directories and ownership ----------------------------------------------
install -d -m0750 -o ntm-server -g ntm-server $L/updates
chown -R ntm-server:ntm-server $E
chmod 0750 $E
chmod 0600 $E/server_key.pem
find $E -maxdepth 1 -type f ! -name server_key.pem -exec chmod 0640 {} +
ok "ownership ntm-server:ntm-server, key 0600, update_dir $L/updates"

[[ -z "$SIWA_ID" ]] && echo "  ! WARNING: no --siwa-service-id — the dashboard will have no way to log in."

cat <<EOF

Next:
  sudo systemctl enable --now ntm-server
  sudo journalctl -u ntm-server -n 30 --no-pager
  curl -s -o /dev/null -w '%{http_code}\n' https://$HOST/login     # expect 200
EOF
