"""The embedded-page gate must validate content across gzip implementations."""
import gzip
import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location('embed_page', Path(__file__).resolve().parents[1] / 'tools/embed_page.py')
embed = importlib.util.module_from_spec(spec)
spec.loader.exec_module(embed)
source = ('<html>Wi-Fi · ' + 'repeated content ' * 100 + '</html>').encode('utf-8')
variants = [gzip.compress(source, compresslevel=level, mtime=0) for level in (1, 9)]
assert variants[0] != variants[1]
for compressed in variants:
    header = embed.render_header(compressed)
    assert embed.matches_source(header, source)
    assert not embed.matches_source(header, source + b'changed')
    assert not embed.matches_source(header + '#define UNEXPECTED 1\n', source)
    assert not embed.matches_source(embed.render_header(compressed[:-3]), source)
    corrupt = bytearray(compressed)
    corrupt[-8] ^= 1  # Corrupt the CRC; matching lengths must not bypass validation.
    assert not embed.matches_source(embed.render_header(corrupt), source)
assert not embed.matches_source(embed.render_header(b'not gzip'), source)
print('PASS: embedded HTML accepts equivalent gzip encodings, rejects stale HTML, corrupt gzip and modified C wrappers')
