import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path


class Store:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.path = self.directory / 'phishguard.sqlite3'
        with self.connect() as db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS analyses (id TEXT PRIMARY KEY, created TEXT, result TEXT);
                CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);
            ''')

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        try:
            with db:
                yield db
        finally:
            db.close()

    def save(self, result):
        with self.connect() as db:
            db.execute('INSERT OR REPLACE INTO analyses VALUES (?,?,?)',
                       (result['analysis_id'], result['created_at'], json.dumps(result, ensure_ascii=False)))

    def get(self, analysis_id):
        with self.connect() as db:
            row = db.execute('SELECT result FROM analyses WHERE id=?', (analysis_id,)).fetchone()
        return json.loads(row[0]) if row else None

    def history(self):
        with self.connect() as db:
            rows = db.execute('SELECT result FROM analyses ORDER BY created DESC LIMIT 100').fetchall()
        return [{k: r[k] for k in ('analysis_id', 'created_at', 'input_type', 'verdict', 'risk_score')}
                for r in (json.loads(row[0]) for row in rows)]

    def setting(self, key, default=None):
        with self.connect() as db:
            row = db.execute('SELECT value FROM settings WHERE key=?', (key,)).fetchone()
        return json.loads(row[0]) if row else default

    def set_setting(self, key, value):
        with self.connect() as db:
            db.execute('INSERT OR REPLACE INTO settings VALUES (?,?)', (key, json.dumps(value)))

    def delete(self, analysis_id):
        with self.connect() as db:
            db.execute('DELETE FROM analyses WHERE id=?', (analysis_id,))
