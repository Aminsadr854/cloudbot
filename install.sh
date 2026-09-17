#!/usr/bin/env bash
#
# cloudbot installer.
#
# Asks for the things that must exist on first boot. Tokens and panel
# creds can still be re-seeded later, but the live bot hard-reads the panel
# all entered inside Telegram afterwards, so this script never handles them and
# no credential of yours ends up in a shell history or a unit file.
set -euo pipefail

DIR=/opt/cloudbot
SERVICE=cloudbot

die() { echo "error: $*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || die "run as root"

echo "── cloudbot installer ──"
read -rp "Bot token (from @BotFather): " TOKEN
[ -n "$TOKEN" ] || die "a token is required"
read -rp "Your numeric Telegram id (the owner): " OWNER
[[ "$OWNER" =~ ^[0-9]+$ ]] || die "the owner id must be numeric"
read -rp "Panel URL (e.g. https://panel.example.com): " PANEL_URL
[ -n "$PANEL_URL" ] || die "panel url is required"
read -rp "Panel username: " PANEL_USER
[ -n "$PANEL_USER" ] || die "panel user is required"
read -rsp "Panel password: " PANEL_PASS
echo
[ -n "$PANEL_PASS" ] || die "panel password is required"

echo "→ installing system packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq python3 python3-venv python3-pip curl >/dev/null

echo "→ installing into $DIR"
install -d -m 755 "$DIR" "$DIR/data" "$DIR/assets"
for f in *.py; do install -m 644 "$f" "$DIR/$f"; done
[ -f assets/paytun ] && install -m 755 assets/paytun "$DIR/assets/paytun"

python3 -m venv "$DIR/venv"
"$DIR/venv/bin/pip" -q install --upgrade pip
"$DIR/venv/bin/pip" -q install aiogram aiohttp aiohttp-socks asyncssh cryptography

umask 077
cat > "$DIR/cloudbot.env" <<ENV
CLOUDBOT_TOKEN=$TOKEN
CLOUDBOT_OWNER=$OWNER
CLOUDBOT_PANEL_URL=$PANEL_URL
CLOUDBOT_PANEL_USER=$PANEL_USER
CLOUDBOT_PANEL_PASS=$PANEL_PASS
CLOUDBOT_DB=$DIR/data/cloudbot.db
CLOUDBOT_KEY=$DIR/data/secret.key
ENV
chmod 600 "$DIR/cloudbot.env"

cat > /etc/systemd/system/$SERVICE.service <<UNIT
[Unit]
Description=Cloud account + node provisioning bot
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$DIR
EnvironmentFile=$DIR/cloudbot.env
ExecStart=$DIR/venv/bin/python $DIR/bot.py
Restart=always
RestartSec=5
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now $SERVICE
sleep 4

if systemctl is-active --quiet $SERVICE; then
  echo
  echo "✅ cloudbot is running."
  echo "   Open the bot in Telegram and send /start to begin."
  echo
  echo "   logs:    journalctl -u $SERVICE -f"
  echo "   restart: systemctl restart $SERVICE"
else
  echo "❌ the service did not start. Last lines:"
  journalctl -u $SERVICE -n 20 --no-pager
  exit 1
fi

# ── probe API (phones report clean-IP measurements) ─────────────
echo "→ setting up probeapi.service"
cat > /etc/systemd/system/probeapi.service <<UNIT2
[Unit]
Description=cloudbot probe API (phones report clean-IP measurements here)
After=network-online.target

[Service]
Type=simple
WorkingDirectory=$DIR
EnvironmentFile=$DIR/cloudbot.env
ExecStart=$DIR/venv/bin/python $DIR/probeapi.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT2

systemctl daemon-reload
systemctl enable --now probeapi

sleep 2
if systemctl is-active --quiet probeapi; then
  echo "✅ probeapi is running."
else
  echo "⚠️  probeapi did not start (non-fatal). Check: journalctl -u probeapi -n 20"
fi

echo
echo "📌 Note: watchdog.py is present but not auto-started."
echo "   To launch tunnels manually: $DIR/venv/bin/python $DIR/watchdog.py &"
echo
echo "✅ Installation complete."
