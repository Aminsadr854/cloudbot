# Datacenter Emojis

This directory contains the downloaded Carbon Design System SVG sources and
the 100×100 PNGs uploaded to Telegram as the `Infrastructure Icons` custom-emoji
set:

<https://t.me/addemoji/datacenter_emojis_by_vpnmanagerkiabot>

The source icons are from IBM Carbon Design System's 32px SVG library and are
licensed under Apache-2.0; the complete notice is in `source/CARBON-LICENSE.txt`.
The renderer keeps the icon geometry, adds a colored circular field, and writes
transparent RGBA PNGs:

```sh
python3 -m pip install cairosvg pillow
python3 build_stickers.py
```

Telegram custom-emoji IDs are recorded in `projects/cloudbot/bot.py`. If the
pack is recreated under a new name, update those IDs after reading them from
`getStickerSet` before deploying the bot.

`PremiumBot` converts normal Unicode emoji in outgoing HTML text, captions,
inline buttons, and reply buttons into these custom emoji IDs. Telegram falls
back to the original Unicode character where the client cannot render the
custom emoji.
