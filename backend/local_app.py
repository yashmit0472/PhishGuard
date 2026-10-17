"""PhishGuard local server. Standard-library runtime; no network analysis dependencies."""
import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sys
import threading
import time
import webbrowser
from collections import defaultdict, deque
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit
from local_core.engine import analyze, MAX_BYTES
from local_core.store import Store
from local_core.feeds import import_feed, status as feed_status

PORT = 5000
ORIGIN = 'http://127.0.0.1:5000'


def data_directory():
    return Path(os.environ.get('PHISHGUARD_DATA_DIR') or
                (Path(os.environ.get('LOCALAPPDATA', Path.home())) / 'PhishGuard'))


def autostart(enabled):
    if sys.platform != 'win32' or not getattr(sys, 'frozen', False):
        raise ValueError('Login startup is available in the packaged Windows app.')
    import winreg
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\Run', 0, winreg.KEY_SET_VALUE) as key:
        if enabled:
            winreg.SetValueEx(key, 'PhishGuard', 0, winreg.REG_SZ, '"' + sys.executable + '" --background')
        else:
            try:
                winreg.DeleteValue(key, 'PhishGuard')
            except FileNotFoundError:
                pass


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, directory, frontend):
        self.store = Store(directory)
        self.frontend = Path(frontend).resolve()
        self.secret = self.store.setting('install_secret')
        if not self.secret:
            self.secret = secrets.token_urlsafe(48)
            self.store.set_setting('install_secret', self.secret)
        self.code = secrets.token_hex(4).upper()
        self.code_expiry = time.monotonic() + 600
        self.sessions, self.attempts = {}, defaultdict(deque)
        self.lock = threading.Lock()
        self.analysis_slots = threading.BoundedSemaphore(2)
        self.model = None
        try:
            from local_core.classifier import TextModel
            self.model = TextModel.load(Path(directory) / 'text-model.json')
        except (FileNotFoundError, ValueError, ImportError):
            pass
        super().__init__(address, Handler)


class Handler(BaseHTTPRequestHandler):
    server_version = 'PhishGuard'

    def log_message(self, *_):
        pass  # Never log message text, indicators, tokens, or query strings.

    def setup(self):
        super().setup()
        self.connection.settimeout(15)

    def respond(self, code, payload, cookie=None):
        body = json.dumps(payload, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        origin = self.headers.get('Origin', '')
        if re.fullmatch(r'chrome-extension://[a-p]{32}', origin) and self.origin_allowed(origin):
            self.send_header('Access-Control-Allow-Origin', origin)
            self.send_header('Vary', 'Origin')
        if cookie:
            self.send_header('Set-Cookie', cookie)
        self.end_headers()
        self.wfile.write(body)

    def origin_allowed(self, origin):
        if origin in ('', ORIGIN):
            return True
        extension_id = self.server.store.setting('extension_id', '')
        return bool(extension_id and origin == 'chrome-extension://' + extension_id)

    def gate(self):
        if self.headers.get('Host') != '127.0.0.1:' + str(self.server.server_port):
            self.respond(403, {'error': 'Invalid local Host.'})
            return False
        origin = self.headers.get('Origin', '')
        # Pairing is permitted from an extension only with the expiring local code.
        pairing = urlsplit(self.path).path == '/api/pair' and re.fullmatch(r'chrome-extension://[a-p]{32}', origin)
        if not self.origin_allowed(origin) and not pairing:
            self.respond(403, {'error': 'Origin is not allowed.'})
            return False
        if self.headers.get('Sec-Fetch-Site') == 'cross-site' and not origin.startswith('chrome-extension://'):
            self.respond(403, {'error': 'Cross-site request denied.'})
            return False
        with self.server.lock:
            bucket = self.server.attempts[self.client_address[0]]
            current = time.monotonic()
            while bucket and bucket[0] < current - 60:
                bucket.popleft()
            if len(bucket) >= 120:
                self.respond(429, {'error': 'Too many requests. Wait one minute.'})
                return False
            bucket.append(current)
        return True

    def authorized(self):
        origin = self.headers.get('Origin', '')
        token = self.headers.get('Authorization', '').removeprefix('Bearer ')
        expected = self.server.store.setting('extension_token', '')
        if token and expected and hmac.compare_digest(token, expected):
            # Non-browser callers holding the secret can use CLI export; browser origin must match.
            return not origin or origin == 'chrome-extension://' + self.server.store.setting('extension_id', '')
        try:
            cookie = SimpleCookie(self.headers.get('Cookie', ''))
            session = cookie.get('pg_session')
            return bool(session and self.server.sessions.get(session.value, 0) > time.time() and origin in ('', ORIGIN))
        except Exception:
            return False

    def do_OPTIONS(self):
        if not self.gate():
            return
        origin = self.headers.get('Origin', '')
        self.send_response(204)
        if self.origin_allowed(origin) or urlsplit(self.path).path == '/api/pair':
            self.send_header('Access-Control-Allow-Origin', origin)
            self.send_header('Access-Control-Allow-Methods', 'GET, POST, DELETE')
            self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
            self.send_header('Access-Control-Allow-Private-Network', 'true')
        self.end_headers()

    def do_GET(self):
        if not self.gate():
            return
        path = urlsplit(self.path).path
        if path == '/health':
            return self.respond(200, {'status': 'ok', 'schema_version': '1.0'})
        if path.startswith('/api/'):
            if not self.authorized():
                return self.respond(401, {'error': 'Unlock or pair with the local app first.'})
            if path == '/api/history':
                return self.respond(200, self.server.store.history())
            if path.startswith('/api/analyses/'):
                record = self.server.store.get(path.rsplit('/', 1)[-1])
                return self.respond(200 if record else 404, record or {'error': 'Analysis not found.'})
            if path == '/api/settings':
                return self.respond(200, {'autostart': self.server.store.setting('autostart', False),
                                         'packaged': bool(getattr(sys, 'frozen', False)),
                                         'extension_paired': bool(self.server.store.setting('extension_id')),
                                         'feeds': feed_status(self.server.store)})
            return self.respond(404, {'error': 'Not found.'})
        # Serve only built assets, never source, data or dotfiles.
        asset = (self.server.frontend / ('index.html' if path == '/' else path.lstrip('/'))).resolve()
        if not asset.is_relative_to(self.server.frontend) or any(p.startswith('.') for p in asset.relative_to(self.server.frontend).parts):
            return self.respond(404, {'error': 'Not found.'})
        if not asset.is_file():
            return self.respond(404, {'error': 'Frontend assets missing. Build frontend first.'})
        import mimetypes
        body = asset.read_bytes()
        self.send_response(200)
        self.send_header('Content-Type', mimetypes.guess_type(str(asset))[0] or 'application/octet-stream')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Content-Security-Policy', "default-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; object-src 'none'; frame-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if not self.gate():
            return
        path = urlsplit(self.path).path
        if path not in ('/api/unlock', '/api/pair') and not self.authorized():
            return self.respond(401, {'error': 'Unlock or pair with the local app first.'})
        try:
            length = int(self.headers.get('Content-Length', '0'))
            if length <= 0 or length > 14 * 1024 * 1024:
                return self.respond(413, {'error': 'Request must be between 1 byte and 14 MiB.'})
            if self.headers.get_content_type() != 'application/json':
                return self.respond(415, {'error': 'JSON is required.'})
            payload = json.loads(self.rfile.read(length))
            if not isinstance(payload, dict):
                raise ValueError('Expected a JSON object.')
            if path in ('/api/unlock', '/api/pair'):
                if time.monotonic() > self.server.code_expiry or not hmac.compare_digest(str(payload.get('code', '')).upper(), self.server.code):
                    return self.respond(403, {'error': 'Code is incorrect or expired. Restart the app for a new code.'})
                if path == '/api/pair':
                    origin = self.headers.get('Origin', '')
                    if not re.fullmatch(r'chrome-extension://[a-p]{32}', origin):
                        raise ValueError('Pair from the extension settings page.')
                    token = secrets.token_urlsafe(48)
                    self.server.store.set_setting('extension_id', origin.split('://')[1])
                    self.server.store.set_setting('extension_token', token)
                    return self.respond(200, {'token': token})
                session = secrets.token_urlsafe(40)
                self.server.sessions[session] = time.time() + 12 * 3600
                return self.respond(200, {'status': 'unlocked'}, 'pg_session=' + session + '; HttpOnly; SameSite=Strict; Path=/; Max-Age=43200')
            if path == '/api/analyze':
                if set(payload) - {'input_type', 'content', 'filename', 'raw_base64', 'gmail_message_id'}:
                    raise ValueError('Unknown analysis field.')
                for key in ('input_type', 'content', 'filename', 'raw_base64', 'gmail_message_id'):
                    if key in payload and not isinstance(payload[key], str):
                        raise ValueError('Analysis fields must be text.')
                raw = base64.b64decode(payload['raw_base64'], validate=True) if payload.get('raw_base64') else None
                if raw and len(raw) > MAX_BYTES:
                    return self.respond(413, {'error': 'File exceeds 10 MiB.'})
                if not self.server.analysis_slots.acquire(blocking=False):
                    return self.respond(429, {'error': 'Two checks are already running. Try again shortly.'})
                try:
                    result = analyze(payload.get('input_type'), payload.get('content', ''), payload.get('filename', ''), raw, self.server.store, self.server.model)
                    if payload.get('gmail_message_id'):
                        if not re.fullmatch(r'[a-fA-F0-9]{8,32}', payload['gmail_message_id']):
                            raise ValueError('Invalid Gmail message ID.')
                        result['gmail_message_id'] = payload['gmail_message_id']
                    self.server.store.save(result)
                finally:
                    self.server.analysis_slots.release()
                return self.respond(200, result)
            if path == '/api/settings':
                if type(payload.get('autostart')) is not bool:
                    raise ValueError('autostart must be true or false.')
                autostart(payload['autostart'])
                self.server.store.set_setting('autostart', payload['autostart'])
                return self.respond(200, {'status': 'saved'})
            if path == '/api/feeds/import':
                return self.respond(200, import_feed(self.server.store, payload))
            if path == '/api/unpair':
                self.server.store.set_setting('extension_token', None)
                self.server.store.set_setting('extension_id', None)
                return self.respond(200, {'status': 'unpaired'})
            if path == '/api/shutdown':
                self.respond(200, {'status': 'stopping'})
                threading.Thread(target=self.server.shutdown, daemon=True).start()
                return
            return self.respond(404, {'error': 'Not found.'})
        except (ValueError, TypeError, KeyError):
            return self.respond(400, {'error': 'Invalid request. Check the input format and limits.'})
        except Exception:
            return self.respond(500, {'error': 'Analysis unavailable. The local operation failed.'})

    def do_DELETE(self):
        if not self.gate():
            return
        if not self.authorized():
            return self.respond(401, {'error': 'Unlock the app first.'})
        path = urlsplit(self.path).path
        if path.startswith('/api/analyses/'):
            self.server.store.delete(path.rsplit('/', 1)[-1])
            return self.respond(200, {'status': 'deleted'})
        return self.respond(404, {'error': 'Not found.'})


def main():
    if '--inspect-worker' in sys.argv:
        from local_core.optional_files import worker
        worker()
        return
    parser = argparse.ArgumentParser()
    parser.add_argument('--background', action='store_true')
    parser.add_argument('--no-browser', action='store_true')
    args = parser.parse_args()
    base = Path(getattr(sys, '_MEIPASS', Path(__file__).resolve().parent.parent))
    try:
        server = Server(('127.0.0.1', PORT), data_directory(), base / 'frontend' / 'dist')
    except OSError:
        if not args.background and not args.no_browser:
            webbrowser.open(ORIGIN)
        print('Port 5000 is already in use. If PhishGuard is not running, close the conflicting service.')
        return
    # Pairing code is intentionally displayed locally, never written to application logs.
    print('PhishGuard: ' + ORIGIN, flush=True)
    print('Local unlock / extension pairing code (10 minutes): ' + server.code, flush=True)
    if not args.background and not args.no_browser:
        webbrowser.open(ORIGIN)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == '__main__':
    main()
