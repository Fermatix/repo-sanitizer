"""Bare base64 raster payloads inside text blobs are blanked like data URIs (e92caaeb)."""
import base64

from repo_sanitizer.redaction.blank_images import Blanker, WHITE_1X1_PNG_B64


def _png_b64(n: int = 400) -> bytes:
    return base64.b64encode(b"\x89PNG\r\n\x1a\n" + bytes(range(256)) * n)


def test_bare_base64_attribute_is_blanked_and_signature_inside_a_longer_run_is_not():
    b = Blanker()
    png = _png_b64()
    xaml = b'<ui:Click ImageBase64="' + png + b'" Text="ok" />\n<other>' + base64.b64encode(b"ZIP" * 300 + b"\x89PNG" + bytes(200)) + b"</other>"
    out = b.blank_data_uris(xaml)
    assert png not in out and b'ImageBase64="' + WHITE_1X1_PNG_B64 + b'"' in out
    assert base64.b64encode(b"ZIP" * 300 + b"\x89PNG" + bytes(200)) in out, "a non-image base64 run is untouched"
    assert b.data_uris == 1
    jpg = base64.b64encode(b"\xff\xd8\xff\xe0" + bytes(range(256)) * 300)
    assert jpg.startswith(b"/9j/4")
    out2 = b.blank_data_uris(b"img: " + jpg + b"\n")
    assert jpg not in out2 and WHITE_1X1_PNG_B64 in out2
    assert b.blank_data_uris(b"nothing here /9j/4short") == b"nothing here /9j/4short"
