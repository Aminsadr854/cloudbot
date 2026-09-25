# Datacenter Emojis

This directory contains the downloaded source SVGs and the 100×100 PNGs uploaded
to Telegram as the `Infrastructure Icons` custom-emoji set:

<https://t.me/addemoji/datacenter_emojis_by_vpnmanagerkiabot>

The generic infrastructure icons are from IBM Carbon Design System's 32px SVG
library and are licensed under Apache-2.0; the complete notice is in
`source/CARBON-LICENSE.txt`. The provider icons are actual Vultr and Hetzner
marks from the Simple Icons repository and the CC0 Linode mark from SVG Repo.
Their source URLs and notices are recorded in `source/PROVIDER-LOGOS.txt`.

The generic renderer keeps the Carbon icon geometry and adds a colored circular
field. Provider rendering only rasterizes the downloaded logo SVGs onto a
transparent canvas, with no generated background or replacement glyph:

```sh
python3 -m pip install cairosvg pillow
python3 build_stickers.py
python3 build_provider_logos.py
```

Telegram custom-emoji IDs are recorded in `projects/cloudbot/bot.py`. If the
pack is recreated under a new name, update those IDs after reading them from
`getStickerSet` before deploying the bot.

`PremiumBot` converts normal Unicode emoji in outgoing HTML text, captions,
inline buttons, and reply buttons into these custom emoji IDs. Provider labels
use the real logo IDs (`🟣 Linode`, `🔷 Vultr`, and `🟦 Hetzner`) with the same
symbols as a fallback. Telegram falls back to the original Unicode character
where the client cannot render the custom emoji.
