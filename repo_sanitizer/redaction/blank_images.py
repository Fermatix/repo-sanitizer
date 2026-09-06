"""White placeholders for raster images (rulepack policy `blank_raster_images: true`, off by default) — every
png/jpeg/gif/webp/bmp/ico/tiff blob in the WHOLE history is replaced
by a blank white image of the SAME format and pixel size under the same path (user decision 2026-09-03: the client
does not need the pictures; the build must not break; nothing of the original picture may ship — logos, photos,
map screenshots, EXIF/XMP metadata with author names and paths all go with it). SVG is text and is NOT touched
(the sweep scrubs its text). Detection is by magic bytes, not by extension, so `.JPG`, mis-named files and
data blobs without an extension are covered; anything Pillow cannot size becomes a 1×1 white image of the
detected format. Rendered bytes are cached per (format, size): a gallery of 800 same-size photos costs one encode."""
from __future__ import annotations

import io
import re
from collections import Counter

MAGIC = (
    (b"\x89PNG\r\n\x1a\n", "PNG"),
    (b"\xff\xd8\xff", "JPEG"),
    (b"GIF87a", "GIF"),
    (b"GIF89a", "GIF"),
    (b"BM", "BMP"),
    (b"\x00\x00\x01\x00", "ICO"),
    (b"II*\x00", "TIFF"),
    (b"MM\x00*", "TIFF"),
)
MAX_PIXELS = 100_000_000      # above this the placeholder keeps the aspect ratio at 8192 on the long side (memory)
FORMATS = ("PNG", "JPEG", "GIF", "WEBP", "BMP", "ICO", "TIFF")


def sniff(data: bytes) -> str | None:
    """Raster format by magic bytes, or None (text, SVG, PDF, fonts, archives, …)."""
    if len(data) < 4:
        return None
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "WEBP"
    for magic, fmt in MAGIC:
        if data.startswith(magic):
            return fmt
    return None


# a raster embedded in a TEXT blob as `data:image/png;base64,…` (CSS background, inline <img>, JSON fixture): the blob
# blanker never sees it because the blob is text. Every such payload becomes this 1×1 white PNG (3a8089e9: a studio
# logo rode along inside a vendored CSS blob — "pictures do not ship at all" applies to those too). SVG stays text.
_DATA_URI_IMG_RE = re.compile(
    rb"data:image/(?:png|jpe?g|gif|webp|bmp|x-icon|vnd\.microsoft\.icon|tiff?)(?:;[a-z0-9=\-]+)*;base64,(?:[A-Za-z0-9+/=]|%2B|%2F|%3D|\s){64,}",
    re.I)
WHITE_1X1_PNG_B64 = (b"iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAAAAAA6fptVAAAACklEQVR4nGP4DwABAQEAWk1v8QAAAABJRU5ErkJggg==")
# A raster stored as a BARE base64 attribute value (UiPath `ImageBase64="iVBOR…"`, e92caaeb: 10 screenshots came through
# byte-identical): the run must START with a raster signature — PNG `iVBORw0KGgo`, JPEG `/9j/4`, GIF `R0lGOD`, WebP
# `UklGRi` — and be at least 200 base64 chars; a signature inside a longer run (a base64 zip holding a JPEG) is left alone.
_BARE_B64_IMG_RE = re.compile(rb"(?<![A-Za-z0-9+/])(?:iVBORw0KGgo|/9j/4|R0lGOD[dl]h|UklGRi)[A-Za-z0-9+/]{200,}={0,2}")
_BARE_B64_HINTS = (b"iVBORw0KGgo", b"/9j/4", b"R0lGOD", b"UklGRi")


class Blanker:
    def __init__(self) -> None:
        self.cache: dict[tuple[str, tuple[int, int]], bytes] = {}
        self.stats: Counter = Counter()          # format -> blobs replaced
        self.data_uris: int = 0                  # base64 data-URI rasters inside text blobs replaced by a 1×1 white PNG
        self.unsized: int = 0                    # blobs Pillow could not size (→ 1×1)
        self.fallback_png: int = 0               # containers Pillow could not write (→ PNG bytes under the old name)
        self.bytes_in = 0
        self.bytes_out = 0

    def size_of(self, data: bytes) -> tuple[int, int] | None:
        try:
            from PIL import Image
            with Image.open(io.BytesIO(data)) as im:   # lazy: reads the header only
                w, h = im.size
            return (int(w), int(h)) if w > 0 and h > 0 else None
        except Exception:  # noqa: BLE001 — corrupt / truncated / bomb-guarded → unsized
            return None

    def blank(self, data: bytes) -> bytes | None:
        """Bytes of a white image like `data` (same format and size), or None when `data` is not a raster image."""
        fmt = sniff(data)
        if fmt is None:
            return None
        size = self.size_of(data)
        if size is None:
            self.unsized += 1
            size = (1, 1)
        if fmt == "ICO":
            size = (min(size[0], 256), min(size[1], 256))
        if size[0] * size[1] > MAX_PIXELS:
            scale = (MAX_PIXELS / (size[0] * size[1])) ** 0.5
            size = (max(1, int(size[0] * scale)), max(1, int(size[1] * scale)))
        key = (fmt, size)
        out = self.cache.get(key)
        if out is None:
            out = self._render(fmt, size)
            self.cache[key] = out
        self.stats[fmt] += 1
        self.bytes_in += len(data)
        self.bytes_out += len(out)
        return out

    def _render(self, fmt: str, size: tuple[int, int]) -> bytes:
        from PIL import Image
        im = Image.new("L", size, 255)           # 1 byte per pixel: a 24 MP photo costs 24 MB transiently
        buf = io.BytesIO()
        kwargs = {"quality": 40} if fmt == "JPEG" else ({"sizes": [size]} if fmt == "ICO" else {})
        try:
            im.save(buf, format=fmt, **kwargs)
        except Exception:  # noqa: BLE001 — a container Pillow cannot write here: still a valid picture, as PNG
            buf = io.BytesIO()
            im.save(buf, format="PNG")
            self.fallback_png += 1
        return buf.getvalue()

    def blank_data_uris(self, data: bytes) -> bytes:
        """Replace every base64 raster data URI inside a TEXT blob by a 1×1 white PNG data URI (mime kept as PNG), and
        every BARE base64 raster payload (an attribute value with no data: prefix) by the bare 1×1 white PNG."""
        if b"base64," in data:
            def repl(m):
                self.data_uris += 1
                self.bytes_in += len(m.group(0))
                self.bytes_out += 22 + len(WHITE_1X1_PNG_B64)
                return b"data:image/png;base64," + WHITE_1X1_PNG_B64
            data = _DATA_URI_IMG_RE.sub(repl, data)
        if any(h in data for h in _BARE_B64_HINTS):
            def repl_bare(m):
                self.data_uris += 1
                self.bytes_in += len(m.group(0))
                self.bytes_out += len(WHITE_1X1_PNG_B64)
                return WHITE_1X1_PNG_B64
            data = _BARE_B64_IMG_RE.sub(repl_bare, data)
        return data

    def report(self) -> dict:
        return {"blobs": sum(self.stats.values()), "by_format": dict(sorted(self.stats.items())),
                "unsized": self.unsized, "fallback_png": self.fallback_png, "data_uris": self.data_uris,
                "bytes_in": self.bytes_in, "bytes_out": self.bytes_out, "svg": "untouched (text)"}
