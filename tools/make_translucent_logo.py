"""Apply real alpha translucency to the teal water body without redrawing the logo."""

from pathlib import Path
from PIL import Image


ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "src" / "Recovery.App" / "Assets"
SOURCE = ASSETS / "yuhen-logo-master.png"
TARGET = ASSETS / "yuhen-logo-translucent-v2.png"


def main() -> None:
    image = Image.open(SOURCE).convert("RGBA")
    pixels = image.load()
    for y in range(image.height):
        for x in range(image.width):
            red, green, blue, alpha = pixels[x, y]
            if alpha == 0:
                continue

            # The water body is teal and green-dominant. Pale data tracks/highlights
            # and the navy disk hub remain opaque for small-icon readability.
            teal_body = green > red + 28 and green >= blue - 18 and red < 155
            navy_hub = blue > green + 18 and green < 100
            if teal_body and not navy_hub:
                luminance = (red * 54 + green * 183 + blue * 19) // 256
                body_alpha = max(188, min(226, 188 + luminance // 6))
                pixels[x, y] = (red, green, blue, min(alpha, body_alpha))

    image.save(TARGET, optimize=True)


if __name__ == "__main__":
    main()
