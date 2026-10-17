import json
from pathlib import Path
root=Path(__file__).resolve().parents[1]
target=root/'dist'/'demo-emails'
target.mkdir(parents=True,exist_ok=True)
for row in json.loads((root/'docs/fixtures/demo.json').read_text(encoding='utf-8')):
    if row['input_type']=='email':
        (target/row['filename']).write_bytes(row['content'].replace('\n','\r\n').encode('utf-8'))
print('Synthetic EML fixtures written to dist/demo-emails.')
