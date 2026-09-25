"""Render the downloaded Carbon datacenter icons as Telegram custom emoji PNGs.

The source SVGs are Apache-2.0 licensed.  This renderer keeps their geometry,
adds a consistent color field, and emits 100x100 RGBA PNGs accepted by the
Telegram custom-emoji sticker API.
"""

from __future__ import annotations

from pathlib import Path

import cairosvg
from PIL import Image, ImageChops, ImageDraw, ImageFilter


ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / "source"
OUT = ROOT / "stickers"

ICONS = {
    "datacenter": ("data--center.svg", "🗄️", (44, 123, 229), (29, 78, 216)),
    "server": ("bare-metal-server.svg", "🖥️", (124, 58, 237), (91, 33, 182)),
    "cloud": ("cloud.svg", "☁️", (14, 165, 233), (3, 105, 161)),
    "firewall": ("firewall.svg", "🛡️", (239, 68, 68), (185, 28, 28)),
    "vpn": ("VPN.svg", "🔐", (16, 185, 129), (4, 120, 87)),
    "database": ("data--base.svg", "💾", (245, 158, 11), (180, 83, 9)),
    "connection": ("connection.svg", "🔗", (6, 182, 212), (14, 116, 144)),
    "backup": ("data-backup.svg", "💽", (99, 102, 241), (67, 56, 202)),
    "ok": ("checkmark--filled.svg", "✅", (34, 197, 94), (21, 128, 61)),
    "error": ("error--filled.svg", "❌", (244, 63, 94), (190, 18, 60)),
}


def _icon_mask(svg_path: Path) -> Image.Image:
    rendered = cairosvg.svg2png(
        url=str(svg_path), output_width=70, output_height=70
    )
    image = Image.open(__import__("io").BytesIO(rendered)).convert("RGBA")
    return image.getchannel("A")


def _gradient(size: int, top: tuple[int, int, int], bottom: tuple[int, int, int]) -> Image.Image:
    image = Image.new("RGBA", (size, size))
    pixels = image.load()
    for y in range(size):
        ratio = y / max(1, size - 1)
        color = tuple(round(top[i] * (1 - ratio) + bottom[i] * ratio) for i in range(3))
        for x in range(size):
            pixels[x, y] = (*color, 255)
    return image


def build_one(name: str, source_name: str, alt: str, top: tuple[int, int, int], bottom: tuple[int, int, int]) -> None:
    canvas = Image.new("RGBA", (100, 100), (0, 0, 0, 0))
    field = _gradient(84, top, bottom)
    mask = Image.new("L", (84, 84), 0)
    ImageDraw.Draw(mask).ellipse((2, 2, 81, 81), fill=255)
    glow = Image.new("RGBA", (84, 84), (255, 255, 255, 0))
    glow.putalpha(mask.filter(ImageFilter.GaussianBlur(7)))
    glow = ImageChops.multiply(glow, Image.new("RGBA", (84, 84), (255, 255, 255, 42)))
    canvas.alpha_composite(glow, (8, 8))
    field.putalpha(mask)
    canvas.alpha_composite(field, (8, 8))

    icon_alpha = _icon_mask(SOURCE / source_name).resize((60, 60), Image.Resampling.LANCZOS)
    # A dark halo keeps white glyphs readable at Telegram's 20-30px display size.
    halo = icon_alpha.filter(ImageFilter.MaxFilter(5))
    halo = ImageChops.subtract(halo, icon_alpha)
    halo_layer = Image.new("RGBA", (60, 60), (15, 23, 42, 160))
    halo_layer.putalpha(halo.point(lambda p: min(180, p)))
    canvas.alpha_composite(halo_layer, (20, 20))
    glyph = Image.new("RGBA", (60, 60), (255, 255, 255, 255))
    glyph.putalpha(icon_alpha)
    canvas.alpha_composite(glyph, (20, 20))
    canvas.save(OUT / f"{name}.png", format="PNG", optimize=True)


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for name, spec in ICONS.items():
        build_one(name, *spec)


if __name__ == "__main__":
    main()
