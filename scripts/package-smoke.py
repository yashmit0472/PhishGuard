"""Test the actual Windows executable on this host, never a clean-machine claim."""
import json
import os
from pathlib import Path
import re
import subprocess
import time
import urllib.request
import urllib.error

root=Path(__file__).resolve().parents[1]
exe=root/'dist/PhishGuard/PhishGuard.exe'
data=root/'.local-test/package-data'
data.mkdir(parents=True,exist_ok=True)
def call(path,body=None,cookie=None):
    req=urllib.request.Request('http://127.0.0.1:5000'+path,data=json.dumps(body).encode() if body is not None else None,
                               headers={'Content-Type':'application/json',**({'Cookie':cookie} if cookie else {})})
    with urllib.request.urlopen(req,timeout=10) as r:return json.load(r),r.headers
def start():
    env=dict(os.environ,PHISHGUARD_DATA_DIR=str(data),PYTHONUNBUFFERED='1')
    # Console output is captured only in-memory; the pairing code is never printed by this test.
    p=subprocess.Popen([str(exe),'--no-browser'],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,
                       creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
    line=p.stdout.readline();code_line=p.stdout.readline()
    match=re.search(r': ([A-F0-9]{8})',code_line)
    if not match:
        p.terminate();raise RuntimeError('Package did not print a local pairing code.')
    for _ in range(30):
        try:
            _,headers=call('/api/unlock',{'code':match.group(1)});return p,headers['Set-Cookie'].split(';')[0]
        except urllib.error.URLError:time.sleep(.1)
    p.terminate();raise RuntimeError('Package startup failed.')
p,cookie=start()
try:
    with urllib.request.urlopen('http://127.0.0.1:5000/',timeout=10) as r:
        assert b'PhishGuard' in r.read()
        assert "connect-src 'self'" in r.headers['Content-Security-Policy']
    try:call('/api/history')
    except urllib.error.HTTPError as e:assert e.code==401
    else:raise AssertionError('History exposed without authentication')
    result,_=call('/api/analyze',{'input_type':'filename','filename':'Invitation.pdf.apk'},cookie)
    assert result['verdict']=='Dangerous'
    result2,_=call('/api/analyze',{'input_type':'file','filename':'invoice.pdf','raw_base64':'TVoxMjM0'},cookie)
    assert result2['verdict']=='Dangerous'
    call('/api/shutdown',{},cookie);p.wait(timeout=10)
    assert p.returncode==0
finally:
    if p.poll() is None:p.terminate();p.wait(timeout=10)
p,cookie=start()
try:
    saved,_=call('/api/analyses/'+result['analysis_id'],cookie=cookie)
    assert saved==result
    call('/api/shutdown',{},cookie);p.wait(timeout=10)
finally:
    if p.poll() is None:p.terminate();p.wait(timeout=10)
index=root/'dist/PhishGuard/_internal/frontend/dist/index.html'
assert index.resolve().is_relative_to((root/'dist').resolve())
missing=index.with_suffix('.temporarily-missing')
index.rename(missing)
try:
    p,cookie=start()
    try:
        try:call('/')
        except urllib.error.HTTPError as e:assert e.code==404
        else:raise AssertionError('Missing frontend assets were not reported')
        call('/api/shutdown',{},cookie);p.wait(timeout=10)
    finally:
        if p.poll() is None:p.terminate();p.wait(timeout=10)
finally:
    missing.rename(index)
report={'host':'Windows development machine','clean_machine':False,'passed':['packaged startup','bundled frontend and CSP','unauthenticated history rejection','disguised APK filename','static PE signature mismatch','graceful shutdown','restart','SQLite cached result survives restart','missing frontend assets produce explicit error'],'not_tested':['Windows login cycle','clean machine','Google OAuth','NVDA']}
(root/'docs/evaluation/package-smoke.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
print(json.dumps(report,indent=2))
