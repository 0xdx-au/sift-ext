#!/usr/bin/env python3
"""Validate the public SIFT GitHub landing page without external dependencies."""
from html.parser import HTMLParser
from pathlib import Path
import re
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
readme = (ROOT / "README.md").read_text(encoding="utf-8")
images = ["docs/media/sift-hero.svg", "docs/media/sift-hero-light.svg", "docs/media/sift-flow.svg", "docs/media/sift-flow-light.svg", "docs/media/sift-mark.svg"]

for filename in images:
    path = ROOT / filename
    assert path.is_file(), f"Missing vector asset: {filename}"
    raw = path.read_text(encoding="utf-8")
    assert "<script" not in raw.lower() and "<foreignobject" not in raw.lower(), filename
    assert not re.search(r'''(?:href|src)\s*=\s*['"]https?://''', raw, re.I), filename
    assert "url(http" not in raw.lower(), filename
    el = ET.fromstring(raw)
    assert el.tag.endswith("svg"), filename
    assert el.attrib.get("viewBox"), f"Missing viewBox in {filename}"
    assert any(child.tag.endswith("title") for child in el), f"Missing accessible title: {filename}"
    assert any(child.tag.endswith("desc") for child in el) or filename.endswith("sift-mark.svg"), filename
    assert len(raw) < 30000, f"SVG unexpectedly large: {filename}"
    assert "M116 22 H140 L240 228" in raw or "sift-flow" in filename, f"ADMINE master Contour-A silhouette missing: {filename}"
    if "sift-hero" in filename:
        assert "#c7a86b" in raw or "#80591f" in raw, f"ADMINE gold accent missing: {filename}"
        assert "#101010" in raw or "#f5f4f0" in raw, f"ADMINE paper/ink background missing: {filename}"

class ImageReader(HTMLParser):
    def __init__(self):
        super().__init__()
        self.sources = []

    def handle_starttag(self, tag, attrs):
        if tag in ("img", "source"):
            source = dict(attrs).get("src") if tag == "img" else dict(attrs).get("srcset")
            assert source, f"{tag} tag missing source path"
            self.sources.append(source)

reader = ImageReader()
reader.feed(readme)
local_images = [src for src in reader.sources if not src.startswith(("https://", "http://"))]
assert len(local_images) >= 4, "Expected both light and dark README artwork"
for source in local_images:
    assert (ROOT / source).is_file(), f"Broken local image path: {source}"

for link in re.findall(r'!?\[[^\]]+\]\(([^)]+)\)', readme):
    if link.startswith(("https://", "http://", "mailto:", "#")):
        continue
    target = link.split("#", 1)[0]
    assert (ROOT / target).exists(), f"Broken local README link: {link}"

for required in ("rights reserved", "not a released browser extension",
                 "not deployed", "SECURITY.md", "engineering/p0-p1-client-20261115"):
    assert required.lower() in readme.lower(), f"Misleading or incomplete README: missing {required}"

print(f"SIFT EXT / ADMINE brand verified: {len(local_images)} light/dark image paths and SVG masters")
