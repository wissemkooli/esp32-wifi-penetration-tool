"""Pack the local dashboard assets into constant firmware flash arrays."""
import argparse
import gzip
import io
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
text = '#pragma once\n#include <stddef.h>\ntypedef struct { const char *path, *mime; const unsigned char *data; size_t size; } web_asset_t;\n'
names = [('dashboard.js','application/javascript'), ('audit-worker.js','application/javascript'), ('style.css','text/css'), ('licenses.txt','text/plain')]
total = 0
for i, (name, mime) in enumerate(names):
    data = (ROOT / 'web/dist' / name).read_bytes()
    output = io.BytesIO()
    with gzip.GzipFile(filename='',fileobj=output,mode='wb',mtime=0) as stream: stream.write(data)
    data = output.getvalue(); total += len(data)
    text += f'static const unsigned char web_asset_{i}[] = {{\n'
    text += ',\n'.join(','.join(f'0x{b:02x}' for b in data[n:n+20]) for n in range(0,len(data),20)) + '\n};\n'
text += 'static const web_asset_t web_assets[] = {\n'
for i,(name,mime) in enumerate(names):
    text += f'{{"/{name}","{mime}",web_asset_{i},sizeof(web_asset_{i})}},\n'
text += '};\n#define WEB_ASSET_COUNT (sizeof(web_assets)/sizeof(web_assets[0]))\n'
if total > 192 * 1024: raise SystemExit('Browser assets exceed the 192 KiB flash budget')
args.output.parent.mkdir(parents=True,exist_ok=True)
args.output.write_text(text,encoding='utf-8',newline='\n')
print(f'Packed offline browser assets: {total} bytes')
