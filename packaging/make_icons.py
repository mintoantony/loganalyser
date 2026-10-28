"""Draw the app icon (three log lines, the middle one highlighted) as .png, .ico and .icns,
and the Windows setup wizard's side banner and corner logo (.bmp, one per screen scale)."""

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

HERE = Path(__file__).parent
SLATE = (14, 22, 31, 255)
LINE = (168, 182, 196, 255)
MARK = (255, 111, 174, 255)


def draw(size: int) -> Image.Image:
    scale = 4  # draw large, then shrink for smooth edges
    s = size * scale
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    pad = int(s * 0.06)
    d.rounded_rectangle((pad, pad, s - pad, s - pad), radius=int(s * 0.22), fill=SLATE)
    left, bar_h = int(s * 0.24), int(s * 0.085)
    for i, (width, color) in enumerate(((0.52, LINE), (0.36, MARK), (0.44, LINE))):
        top = int(s * (0.30 + i * 0.17))
        d.rounded_rectangle((left, top, left + int(s * width), top + bar_h), radius=bar_h // 2, fill=color)
    return img.resize((size, size), Image.LANCZOS)


# Inno Setup picks the best file for the screen scale: 100%, 125%, 150%, 200%.
WIZARD_SCALES = (1.0, 1.25, 1.5, 2.0)


def _font(size: int) -> ImageFont.ImageFont:
    for name in ("segoeuib.ttf", "arialbd.ttf", "DejaVuSans-Bold.ttf"):
        try:
            return ImageFont.truetype(name, size)
        except OSError:
            continue
    return ImageFont.load_default()


def sidebar(scale: float) -> Image.Image:
    """The tall banner on the welcome and finish pages: a column of log lines, one highlighted."""
    w, h = round(164 * scale), round(314 * scale)
    img = Image.new("RGB", (w, h), SLATE[:3])
    d = ImageDraw.Draw(img)
    left, bar_h, gap = round(18 * scale), max(2, round(6 * scale)), round(14 * scale)
    widths = (0.62, 0.48, 0.70, 0.40, 0.56, 0.66, 0.44, 0.58, 0.36, 0.64, 0.50)
    for i, width in enumerate(widths):
        top = round(28 * scale) + i * gap
        color = MARK if i == 5 else (46, 62, 78, 255)
        d.rounded_rectangle((left, top, left + round((w - 2 * left) * width), top + bar_h),
                            radius=bar_h // 2, fill=color[:3])
    logo = draw(round(44 * scale)).convert("RGBA")
    img.paste(logo, (left - round(4 * scale), h - round(108 * scale)), logo)
    d.text((left, h - round(56 * scale)), "LogAnalyser", font=_font(round(19 * scale)), fill=(236, 241, 245))
    d.text((left, h - round(30 * scale)), "Find out why it broke", font=_font(round(10 * scale)), fill=(168, 182, 196))
    return img


def corner(scale: float) -> Image.Image:
    """The small logo at the top right of the inner wizard pages."""
    size = round(55 * scale)
    img = Image.new("RGB", (size, size), (255, 255, 255))
    logo = draw(size).convert("RGBA")
    img.paste(logo, (0, 0), logo)
    return img


def mac_pkg_background(scale: int) -> Image.Image:
    """Art for the bottom left of the Mac installer, under its list of steps. Transparent, with
    mid-tone lines, so it works in light and dark mode."""
    w, h = 200 * scale, 230 * scale
    img = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    left, bar_h, gap = 22 * scale, 5 * scale, 13 * scale
    for i, width in enumerate((0.62, 0.48, 0.70, 0.40, 0.56, 0.66, 0.44, 0.58, 0.36, 0.64)):
        top = 30 * scale + i * gap
        color = MARK if i == 5 else (138, 151, 165, 110)
        d.rounded_rectangle((left, top, left + round((w - 2 * left) * width), top + bar_h), radius=bar_h // 2, fill=color)
    logo = draw(40 * scale)
    img.alpha_composite(logo, (left - 3 * scale, h - 62 * scale))
    return img


def mac_dmg_background(scale: int) -> Image.Image:
    """The disk image window: app on the left, Applications on the right, an arrow between them.
    The icons themselves are placed by build_mac.sh at x=170 and x=490, y=190 (1x points)."""
    w, h = 660 * scale, 400 * scale
    img = Image.new("RGB", (w, h), (244, 246, 248))
    d = ImageDraw.Draw(img)
    ink, soft = (14, 22, 31), (92, 104, 117)
    d.text((w // 2, 52 * scale), "Install LogAnalyser", font=_font(26 * scale), fill=ink, anchor="mm")
    d.text((w // 2, 86 * scale), "Drag LogAnalyser onto the Applications folder", font=_font(14 * scale), fill=soft, anchor="mm")
    y, x1, x2 = 190 * scale, 252 * scale, 408 * scale
    d.line((x1, y, x2 - 14 * scale, y), fill=MARK[:3], width=6 * scale)
    d.polygon([(x2, y), (x2 - 22 * scale, y - 14 * scale), (x2 - 22 * scale, y + 14 * scale)], fill=MARK[:3])
    note = ("The first time you open it, if macOS says it cannot check the app,",
            "go to System Settings > Privacy & Security and click Open Anyway.")
    for i, line in enumerate(note):
        d.text((w // 2, (352 + 18 * i) * scale), line, font=_font(11 * scale), fill=soft, anchor="mm")
    return img


def main() -> None:
    big = draw(1024)
    big.save(HERE / "icon.png")
    big.save(HERE / "icon.ico", sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
    big.save(HERE / "icon.icns")
    for scale in WIZARD_SCALES:
        suffix = f"-{round(scale * 100)}"
        sidebar(scale).save(HERE / f"wizard-sidebar{suffix}.bmp")
        corner(scale).save(HERE / f"wizard-small{suffix}.bmp")
    # Mac installer art, at 1x and 2x (build_mac.sh joins each pair into one Retina-ready .tiff).
    for scale, suffix in ((1, ""), (2, "@2x")):
        mac_pkg_background(scale).save(HERE / f"mac-pkg-background{suffix}.png")
        mac_dmg_background(scale).save(HERE / f"mac-dmg-background{suffix}.png")
    print("Wrote icon.png, icon.ico, icon.icns, the Windows setup wizard images and the Mac installer art")


if __name__ == "__main__":
    main()
