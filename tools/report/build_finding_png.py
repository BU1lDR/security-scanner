"""Render one finding out of the sample report as a PNG for the LinkedIn entry.

The point of this image is that a human triaged the output, so it uses the
report's own stylesheet and the finding's verbatim text -- it is a crop of the
document, not a graphic. Window width is set so the text measure matches the
printed A4 page (16mm margins on 210mm -> ~672 CSS px), which is why the result
looks like the PDF rather than like a web page.

Usage: python build_finding_png.py <start-line> <end-line> <out.png>
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from PIL import Image

import md2html

HERE = Path(__file__).parent
REPORT = HERE / "sample-report-pygoat.md"
EDGE = Path(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe")

WINDOW_W = 700          # CSS px -> text measure ~= the printed page
WINDOW_H = 2600         # generous; trimmed to content afterwards
SCALE = 2               # retina-ish, so the text is legible when opened
PAD = 20                # CSS px of whitespace kept around the crop


def main() -> int:
    start, end, out_name = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]

    lines = REPORT.read_text(encoding="utf-8").split("\n")
    excerpt = "\n".join(lines[start - 1:end])
    if not excerpt.strip().startswith("## F-"):
        print(f"refusing: line {start} is not a finding heading", file=sys.stderr)
        return 2

    html_path = HERE / "_finding_excerpt.html"
    html_path.write_text(md2html.convert(excerpt), encoding="utf-8")

    raw = HERE / "_finding_raw.png"
    raw.unlink(missing_ok=True)
    url = "file:///" + str(html_path).replace("\\", "/")
    subprocess.run(
        [
            str(EDGE), "--headless=new", "--disable-gpu", "--hide-scrollbars",
            f"--force-device-scale-factor={SCALE}",
            f"--window-size={WINDOW_W},{WINDOW_H}",
            f"--screenshot={raw}", url,
        ],
        check=True, capture_output=True, timeout=120,
    )
    if not raw.exists():
        print("refusing: Edge produced no screenshot", file=sys.stderr)
        return 2

    img = Image.open(raw).convert("RGB")
    # Content sits on white; invert so the ink becomes the bounding box.
    from PIL import ImageChops
    bg = Image.new("RGB", img.size, (255, 255, 255))
    bbox = ImageChops.difference(img, bg).getbbox()
    if bbox is None:
        print("refusing: rendered page is blank", file=sys.stderr)
        return 2

    pad = PAD * SCALE
    left = max(0, bbox[0] - pad)
    top = max(0, bbox[1] - pad)
    right = min(img.width, bbox[2] + pad)
    bottom = min(img.height, bbox[3] + pad)
    if bottom >= img.height - 1:
        print(f"warning: content reached the bottom of a {WINDOW_H}px window -- "
              f"it may be cut off; raise WINDOW_H", file=sys.stderr)

    cropped = img.crop((left, top, right, bottom))
    out = HERE / out_name
    cropped.save(out, optimize=True)

    raw.unlink(missing_ok=True)
    html_path.unlink(missing_ok=True)
    print(f"{out.name}: {cropped.width}x{cropped.height}px, {out.stat().st_size:,} bytes "
          f"(report lines {start}-{end})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
