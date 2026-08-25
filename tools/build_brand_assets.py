"""Generate deterministic Windows/UI sizes from the approved master logo."""

from pathlib import Path
from PIL import Image


ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "src" / "Recovery.App" / "Assets"
MASTER = ASSETS / "yuhen-logo-master.png"
TRANSLUCENT_MASTER = ASSETS / "yuhen-logo-translucent-v2.png"


def square_variant(source: Image.Image, size: int) -> Image.Image:
    canvas = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    margin = max(1, round(size * 0.04))
    fitted = source.copy()
    fitted.thumbnail((size - margin * 2, size - margin * 2), Image.Resampling.LANCZOS)
    canvas.alpha_composite(fitted, ((size - fitted.width) // 2, (size - fitted.height) // 2))
    return canvas


def main() -> None:
    source = Image.open(TRANSLUCENT_MASTER if TRANSLUCENT_MASTER.exists() else MASTER).convert("RGBA")
    # Remove unused transparent margins while retaining a little breathing room in each output.
    alpha_box = source.getchannel("A").getbbox()
    if alpha_box is None:
        raise RuntimeError("Master logo has no visible pixels")
    source = source.crop(alpha_box)

    icon_512 = square_variant(source, 512)
    icon_512.save(ASSETS / "yuhen-icon-512.png", optimize=True)
    square_variant(source, 256).save(ASSETS / "yuhen-ui-256.png", optimize=True)
    icon_512.save(
        ASSETS / "yuhen.ico",
        format="ICO",
        sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)],
    )


if __name__ == "__main__":
    main()
