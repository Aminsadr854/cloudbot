"""Create the Datacenter Emojis custom-emoji set through the Bot API.

The script deliberately reads the bot token from the environment.  It is safe
to stream over SSH because it never writes the token or a copy of it to disk.
"""

from __future__ import annotations

import json
import os
import uuid
from pathlib import Path
from urllib import request
from urllib.parse import urlencode


PACK_NAME = "datacenter_emojis_by_vpnmanagerkiabot"
PACK_TITLE = "Infrastructure Icons"
OWNER_ID = os.environ.get("CLOUDBOT_OWNER", "")
TOKEN = os.environ["CLOUDBOT_TOKEN"]
ASSET_DIR = Path(os.environ["EMOJI_DIR"])

ASSETS = [
    ("datacenter", "🗄️", ["datacenter", "server room", "rack"]),
    ("server", "🖥️", ["server", "bare metal", "compute"]),
    ("cloud", "☁️", ["cloud", "hosting", "provider"]),
    ("firewall", "🛡️", ["firewall", "security", "blocked"]),
    ("vpn", "🔐", ["vpn", "tunnel", "encrypted"]),
    ("database", "💾", ["database", "storage", "disk"]),
    ("connection", "🔗", ["network", "connection", "link"]),
    ("backup", "💽", ["backup", "restore", "snapshot"]),
    ("ok", "✅", ["ok", "healthy", "success"]),
    ("error", "❌", ["error", "failed", "problem"]),
]


def multipart(fields: dict[str, str], files: dict[str, tuple[str, bytes, str]]) -> tuple[bytes, str]:
    boundary = f"----cloudbot-{uuid.uuid4().hex}"
    chunks: list[bytes] = []
    for name, value in fields.items():
        chunks.extend([
            f"--{boundary}\r\n".encode(),
            f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode(),
            value.encode(),
            b"\r\n",
        ])
    for name, (filename, content, content_type) in files.items():
        chunks.extend([
            f"--{boundary}\r\n".encode(),
            f'Content-Disposition: form-data; name="{name}"; filename="{filename}"\r\n'.encode(),
            f"Content-Type: {content_type}\r\n\r\n".encode(),
            content,
            b"\r\n",
        ])
    chunks.append(f"--{boundary}--\r\n".encode())
    return b"".join(chunks), f"multipart/form-data; boundary={boundary}"


def call(method: str, fields: dict[str, str], files: dict[str, tuple[str, bytes, str]] | None = None) -> dict:
    url = f"https://api.telegram.org/bot{TOKEN}/{method}"
    if files:
        body, content_type = multipart(fields, files)
        req = request.Request(url, data=body, headers={"Content-Type": content_type})
    else:
        body = urlencode(fields).encode()
        req = request.Request(url, data=body, headers={"Content-Type": "application/x-www-form-urlencoded"})
    with request.urlopen(req, timeout=60) as response:
        result = json.load(response)
    if not result.get("ok"):
        raise RuntimeError(f"{method}: {result.get('description', 'Telegram API error')}")
    return result


def main() -> None:
    if not OWNER_ID.isdigit():
        raise SystemExit("CLOUDBOT_OWNER must be set to the numeric sticker-set owner id")
    stickers = []
    files = {}
    for index, (name, emoji, keywords) in enumerate(ASSETS):
        field = f"sticker{index}"
        stickers.append({
            "sticker": f"attach://{field}",
            "format": "static",
            "emoji_list": [emoji],
            "keywords": keywords,
        })
        path = ASSET_DIR / f"{name}.png"
        files[field] = (path.name, path.read_bytes(), "image/png")
    result = call(
        "createNewStickerSet",
        {
            "user_id": OWNER_ID,
            "name": PACK_NAME,
            "title": PACK_TITLE,
            "stickers": json.dumps(stickers, ensure_ascii=False, separators=(",", ":")),
            "sticker_type": "custom_emoji",
            "needs_repainting": "false",
        },
        files,
    )
    print(json.dumps({"created": result["result"], "name": PACK_NAME}, ensure_ascii=False))


if __name__ == "__main__":
    main()
