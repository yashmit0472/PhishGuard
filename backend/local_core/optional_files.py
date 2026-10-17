"""Opt-in reuse of existing OCR/QR and macro tools in a disposable worker.

Not enabled in the minimal package. Entire batch has an 8-second wall-time budget.
Archives are inspected only for bounded metadata, never recursively extracted.
"""
import base64
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import zipfile


def inspect_batch(attachments):
    if os.environ.get('PHISHGUARD_DEEP_INSPECTION') != '1':
        return {}, 'unavailable', 'Optional OCR/QR and macro tools are disabled in this build.'
    payload=[{'filename':name,'data':base64.b64encode(data).decode()} for name,data in attachments if data is not None]
    command=[sys.executable, '--inspect-worker'] if getattr(sys,'frozen',False) else [sys.executable,str(Path(__file__).resolve().parents[1]/'local_app.py'),'--inspect-worker']
    try:
        child=subprocess.run(command,input=json.dumps(payload),capture_output=True,text=True,timeout=8,
                             creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        if child.returncode or len(child.stdout)>500000:
            return {},'failed','Optional file worker failed; basic static checks remain available.'
        return json.loads(child.stdout),'completed','Optional file checks ran in a disposable process.'
    except subprocess.TimeoutExpired:
        return {},'failed','Optional file inspection exceeded 8 seconds and was terminated.'
    except (OSError,ValueError):
        return {},'failed','Optional file inspection could not run.'


def worker():
    payload=json.loads(sys.stdin.read(14*1024*1024))
    results={}
    for row in payload[:20]:
        name=row['filename'];raw=base64.b64decode(row['data'],validate=True)
        if len(raw)>10*1024*1024:continue
        entry={'macros':'unavailable','image':'unavailable','ocr_text':'','qr_urls':[]}
        ext=name.lower().rsplit('.',1)[-1]
        if ext in ('doc','xls','ppt','docx','xlsx','pptx','docm','xlsm','pptm') and importlib.util.find_spec('oletools'):
            permitted=True
            if raw.startswith(b'PK'):
                with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                    members=archive.infolist()
                    permitted=len(members)<=200 and sum(m.file_size for m in members)<=20*1024*1024 and all(m.file_size/max(1,m.compress_size)<=100 for m in members)
            if permitted:
                from forensics.macro_scan import analyze_macro_behavior
                entry['macro_result']=analyze_macro_behavior(raw,name)
                entry['macros']='completed'
            else:entry['macros']='limit exceeded'
        if ext in ('png','jpg','jpeg') and importlib.util.find_spec('PIL') and importlib.util.find_spec('cv2'):
            from PIL import Image
            Image.MAX_IMAGE_PIXELS=4000000
            with Image.open(io.BytesIO(raw)) as image:
                if image.width*image.height<=4000000:
                    from forensics.image_forensics import scan_image_attachment
                    entry.update(scan_image_attachment(raw,name));entry['image']='partial'
                    # Existing scanner degrades silently; do not claim full OCR/QR coverage.
        results[name]=entry
    sys.stdout.write(json.dumps(results,ensure_ascii=True))
