"""Render downloaded provider logo SVGs as transparent Telegram PNG assets.

The SVGs in ``source/`` are the provider marks downloaded from Simple Icons
(Vultr and Hetzner) and SVG Repo's CC0 Linode asset.  This script only rasterizes
those files and scales them onto a transparent canvas; it does not draw a
background, badge, or replacement logo.
"""

from __future__ import annotations

import io
from pathlib import Path

import cairosvg
from PIL import Image


ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / "source"
OUT = ROOT / "stickers"

PROVIDER_LOGOS = {
    "linode": "linode.svg",
    "vultr": "vultr.svg",
    "hetzner": "hetzner.svg",
}


def build_one(name: str, source_name: str) -> None:
    rendered = cairosvg.svg2png(
        url=str(SOURCE / source_name), output_width=100, output_height=100
    )
    source = Image.open(io.BytesIO(rendered)).convert("RGBA")
    bbox = source.getbbox()
    if bbox:
        source = source.crop(bbox)
    scale = min(86 / source.width, 86 / source.height, 1)
    size = (max(1, round(source.width * scale)), max(1, round(source.height * scale)))
    source = source.resize(size, Image.Resampling.LANCZOS)
    canvas = Image.new("RGBA", (100, 100), (0, 0, 0, 0))
    canvas.alpha_composite(source, ((100 - size[0]) // 2, (100 - size[1]) // 2))
    canvas.save(OUT / f"{name}.png", format="PNG", optimize=True)


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for name, source_name in PROVIDER_LOGOS.items():
        build_one(name, source_name)


if __name__ == "__main__":
    main()
