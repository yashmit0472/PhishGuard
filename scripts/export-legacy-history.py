"""Convert an explicitly exported legacy JSON file into redacted archival summaries.

Does not connect to MongoDB, delete records, or reinterpret legacy scores as v1 verdicts.
"""
import argparse
import json
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'backend'))
from local_core.engine import display

p=argparse.ArgumentParser();p.add_argument('input');p.add_argument('output');a=p.parse_args()
source=Path(a.input);target=Path(a.output)
if source.resolve()==target.resolve() or target.exists():
    raise SystemExit('Choose a new output file. Original data is never overwritten.')
rows=json.loads(source.read_text(encoding='utf-8-sig'))
if not isinstance(rows,list):raise SystemExit('Expected a JSON array exported from MongoDB or browser history.')
clean=[]
for row in rows:
    report=row.get('fullReport') or row.get('report') or row
    clean.append({'legacy_id':str(report.get('email_id',row.get('id',row.get('_id','')))),
                  'legacy_verdict':display(report.get('verdict','Unknown')),
                  'legacy_risk_score':report.get('risk_score'),
                  'warning':'Archived legacy assessment; not a v1 local analysis. Recheck original email for a current verdict.'})
target.write_text(json.dumps({'archive_schema':'legacy-summary-1','records':clean},indent=2),encoding='utf-8')
print(f'Exported {len(clean)} archival summaries. Original data was not changed.')
