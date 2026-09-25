"""Add the downloaded provider logo stickers to the existing custom-emoji set."""

from __future__ import annotations

import json
import os
from pathlib import Path

from register_pack import call


OWNER_ID = os.environ.get("CLOUDBOT_OWNER", "")
PACK_NAME = "datacenter_emojis_by_vpnmanagerkiabot"
ASSET_DIR = Path(os.environ["EMOJI_DIR"])

PROVIDER_ASSETS = [
    ("linode", "🟣", ["Linode", "provider", "cloud"]),
    ("vultr", "🔷", ["Vultr", "provider", "cloud"]),
    ("hetzner", "🟦", ["Hetzner", "provider", "cloud"]),
]


def main() -> None:
    if not OWNER_ID.isdigit():
        raise SystemExit("CLOUDBOT_OWNER must be set to the numeric sticker-set owner id")
    added = []
    for name, emoji, keywords in PROVIDER_ASSETS:
        path = ASSET_DIR / f"{name}.png"
        result = call(
            "addStickerToSet",
            {
                "user_id": OWNER_ID,
                "name": PACK_NAME,
                "sticker": json.dumps(
                    {
                        "sticker": "attach://sticker",
                        "format": "static",
                        "emoji_list": [emoji],
                        "keywords": keywords,
                    },
                    ensure_ascii=False,
                    separators=(",", ":"),
                ),
            },
            {"sticker": (path.name, path.read_bytes(), "image/png")},
        )
        added.append({"name": name, "result": result["result"]})
    print(json.dumps({"added": added, "name": PACK_NAME}, ensure_ascii=False))


if __name__ == "__main__":
    main()
