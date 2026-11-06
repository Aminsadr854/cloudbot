"""Owner-notification webhook: external scripts POST a message, the owner gets it in Telegram.

Deliberately separate from the control API token: a monitoring script holds
only a token that can send a message to the owner, not one that can create or
delete servers.
"""
import hmac
import html
import logging
import os
import re
import time
from collections import deque
from pathlib import Path

import aiohttp
from aiohttp import web

log = logging.getLogger("cloudbot.webhook")

WEBHOOK_PATH = "/v1/webhook/notify"
TOKEN_PATH = Path(os.environ.get("CLOUDBOT_WEBHOOK_TOKEN_FILE",
                                 "/opt/cloudbot/data/webhook.token"))
MAX_MESSAGE = 3500
MAX_TITLE = 200
RATE_LIMIT = 30          # messages ...
RATE_WINDOW = 600        # ... per ten minutes
LEVELS = {"info": "ℹ️", "warning": "🟡 Warning", "critical": "🔴 Problem", "ok": "🟢 OK"}

# Inline buttons are limited to the tunnel-doctor namespace: the notify token must
# never be able to forge callbacks for the bot's own menus (delete server, ...).
BUTTON_DATA = re.compile(r"td:[a-z]{1,8}:[A-Za-z0-9_.-]{1,48}")
MAX_BUTTON_ROWS = 3

TOKEN_KEY = web.AppKey("webhook_token", str)
SEND_KEY = web.AppKey("webhook_send", object)
SENT_KEY = web.AppKey("webhook_sent", deque)


def read_token(path=None):
    """Return the webhook token, or None when the webhook is not enabled."""
    try:
        token = Path(path or TOKEN_PATH).read_text(encoding="utf-8").strip()
    except OSError:
        return None
    if len(token) < 32:
        raise RuntimeError("webhook token must be at least 32 characters")
    return token


def format_message(level, title, message):
    icon = LEVELS.get(level, LEVELS["info"])
    head = f"{icon} <b>{html.escape(title)}</b>\n" if title else f"{icon} "
    return head + html.escape(message)


def parse_buttons(raw):
    """[[{"text", "data"}, ...], ...] -> Telegram inline_keyboard, or None. Raises ValueError."""
    if raw in (None, []):
        return None
    if not isinstance(raw, list) or len(raw) > MAX_BUTTON_ROWS:
        raise ValueError("buttons must be a list of at most 3 rows")
    rows = []
    for row in raw:
        if not isinstance(row, list) or not 1 <= len(row) <= 3:
            raise ValueError("each button row holds 1-3 buttons")
        out = []
        for b in row:
            text, data = (b.get("text"), b.get("data")) if isinstance(b, dict) else (None, None)
            if not isinstance(text, str) or not 0 < len(text) <= 40 or not isinstance(data, str) \
                    or not BUTTON_DATA.fullmatch(data):
                raise ValueError("invalid button")
            out.append({"text": text, "callback_data": data})
        rows.append(out)
    return {"inline_keyboard": rows}


async def telegram_send(text, markup=None):
    """Send text to the owner through the Telegram Bot API."""
    bot_token = os.environ["CLOUDBOT_TOKEN"]
    owner = int(os.environ["CLOUDBOT_OWNER"])
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = {"chat_id": owner, "text": text, "parse_mode": "HTML",
               "disable_web_page_preview": True}
    if markup:
        payload["reply_markup"] = markup
    timeout = aiohttp.ClientTimeout(total=20)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.post(url, json=payload) as resp:
            if resp.status != 200:
                raise RuntimeError(f"Telegram returned HTTP {resp.status}")


def authorized(request):
    expected = request.app.get(TOKEN_KEY)
    header = request.headers.get("Authorization", "")
    supplied = header[7:] if header.startswith("Bearer ") else ""
    return bool(expected and supplied and hmac.compare_digest(supplied, expected))


async def notify(request):
    """POST {"message": str, "title"?: str, "level"?: info|warning|critical|ok,
    "buttons"?: [[{"text": str, "data": "td:<verb>:<ref>"}]]}."""
    if not request.app.get(TOKEN_KEY):
        return web.json_response({"error": "webhook is not enabled"}, status=404)
    if not authorized(request):
        return web.json_response({"error": "unauthorized"}, status=401)
    try:
        body = await request.json()
    except (ValueError, UnicodeDecodeError):
        body = None
    if not isinstance(body, dict):
        return web.json_response({"error": "body must be a JSON object"}, status=400)
    message = body.get("message")
    title = body.get("title") or ""
    level = body.get("level") or "info"
    if not isinstance(message, str) or not message.strip():
        return web.json_response({"error": "message is required"}, status=400)
    if not isinstance(title, str) or level not in LEVELS:
        return web.json_response({"error": "invalid title or level"}, status=400)
    if len(message) > MAX_MESSAGE or len(title) > MAX_TITLE:
        return web.json_response({"error": "message or title too long"}, status=413)
    try:
        markup = parse_buttons(body.get("buttons"))
    except ValueError as e:
        return web.json_response({"error": str(e)}, status=400)

    sent = request.app[SENT_KEY]
    now = time.monotonic()
    while sent and now - sent[0] > RATE_WINDOW:
        sent.popleft()
    if len(sent) >= RATE_LIMIT:
        return web.json_response({"error": "rate limited"}, status=429)
    try:
        text = format_message(level, title.strip(), message.strip())
        send = request.app[SEND_KEY]
        await (send(text, markup) if markup else send(text))
    except Exception:
        log.exception("webhook notification could not be delivered")
        return web.json_response({"error": "delivery failed"}, status=502)
    sent.append(now)
    return web.json_response({"sent": True})


def install(app, token=None, send=None):
    """Register the webhook on app; a missing token leaves it answering 404."""
    app[TOKEN_KEY] = token if token is not None else (read_token() or "")
    app[SEND_KEY] = send or telegram_send
    app[SENT_KEY] = deque()
    app.router.add_post(WEBHOOK_PATH, notify)
