"""Draws the ProxyHive icon (a small honeycomb of three cells) and writes assets/proxyhive.ico + .png.

    python scripts/make_icon.py          (needs Pillow; only used when you want to change the icon)
"""
import math
from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter

OUT = Path(__file__).resolve().parent.parent / "assets"
S = 1024                                  # draw big, shrink for smooth edges
CELLS = [("#5eead4", 90), ("#38bdf8", 210), ("#7c9cff", 330)]      # colour, direction from the centre of the cluster


def hexagon(cx: float, cy: float, r: float) -> list[tuple[float, float]]:
    """Pointy-top hexagon."""
    return [(cx + r * math.cos(math.radians(90 + 60 * i)), cy - r * math.sin(math.radians(90 + 60 * i))) for i in range(6)]


def cluster() -> list[tuple[str, float, float, float]]:
    r = 176                                # cell radius
    gap = 1.07                             # spacing between neighbouring cells
    cx, cy = S / 2, S / 2 + 18
    out = []
    for colour, ang in CELLS:
        out.append((colour, cx + r * gap * math.cos(math.radians(ang)), cy - r * gap * math.sin(math.radians(ang)), r))
    return out


def draw() -> Image.Image:
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    # dark rounded tile with a soft vertical gradient
    tile = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    grad = Image.linear_gradient("L").resize((S, S))
    top, bottom = Image.new("RGB", (S, S), "#142036"), Image.new("RGB", (S, S), "#070a10")
    tile.paste(Image.composite(bottom, top, grad), (0, 0))
    mask = Image.new("L", (S, S), 0)
    ImageDraw.Draw(mask).rounded_rectangle((24, 24, S - 24, S - 24), radius=230, fill=255)
    tile.putalpha(mask)
    img.alpha_composite(tile)
    # a faint border
    ImageDraw.Draw(img).rounded_rectangle((24, 24, S - 24, S - 24), radius=230, outline=(94, 234, 212, 70), width=6)
    # glow behind the cells
    glow = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    gd = ImageDraw.Draw(glow)
    for colour, x, y, r in cluster():
        gd.polygon(hexagon(x, y, r * 1.05), fill=colour + "99")
    img.alpha_composite(glow.filter(ImageFilter.GaussianBlur(34)))
    # the cells, each with a lighter inner edge so they read as honeycomb at any size
    d = ImageDraw.Draw(img)
    for colour, x, y, r in cluster():
        d.polygon(hexagon(x, y, r), fill=colour)
    shine = Image.new("RGBA", (S, S), (0, 0, 0, 0))          # blended on top: ImageDraw would overwrite the pixels
    sd = ImageDraw.Draw(shine)
    for colour, x, y, r in cluster():
        sd.polygon(hexagon(x, y, r * 0.62), fill=(255, 255, 255, 70))
    img.alpha_composite(shine)
    return img


def svg() -> str:
    cells = "".join(f'<polygon points="{" ".join(f"{px:.0f},{py:.0f}" for px, py in hexagon(x, y, r))}" fill="{c}"/>'
                    for c, x, y, r in cluster())
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {S} {S}"><rect x="24" y="24" width="{S - 48}" height="{S - 48}" '
            f'rx="230" fill="#0c1424"/>{cells}</svg>')


if __name__ == "__main__":
    OUT.mkdir(exist_ok=True)
    big = draw()
    big.resize((512, 512), Image.LANCZOS).save(OUT / "proxyhive.png")
    sizes = [256, 128, 64, 48, 32, 24, 16]
    frames = [big.resize((n, n), Image.LANCZOS) for n in sizes]
    frames[0].save(OUT / "proxyhive.ico", format="ICO", sizes=[(n, n) for n in sizes], append_images=frames[1:])
    (OUT / "favicon.svg").write_text(svg(), encoding="utf-8")
    print("wrote", [p.name for p in sorted(OUT.iterdir())])
