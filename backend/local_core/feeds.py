"""User-supplied offline intelligence; validation and atomic replacement, no downloader."""
import json
import hashlib
from datetime import datetime, timezone


def now():
    return datetime.now(timezone.utc).isoformat()


def import_feed(store, payload):
    try:
        if not isinstance(payload, dict) or payload.get('license_accepted') is not True:
            raise ValueError('Confirm that you have permission to use this dataset.')
        rows = payload.get('indicators')
        if not isinstance(rows, list) or not 1 <= len(rows) <= 100000:
            raise ValueError('Expected 1–100000 indicators.')
        published = datetime.fromisoformat(payload['published_at'].replace('Z', '+00:00'))
        if published.tzinfo is None or published > datetime.now(timezone.utc):
            raise ValueError('Dataset timestamp must include a timezone and cannot be in the future.')
        clean = []
        for row in rows:
            if row.get('type') not in ('url', 'domain', 'sha256') or not isinstance(row.get('value'), str):
                raise ValueError('Invalid indicator.')
            value = row['value'].strip()
            if not value or len(value) > 4096:
                raise ValueError('Invalid indicator length.')
            clean.append({'type': row['type'], 'digest': hashlib.sha256(value.encode()).hexdigest()})
        feed = {'name': str(payload.get('name', 'User dataset'))[:100],
                'published_at': published.isoformat(), 'imported_at': now(), 'indicators': clean,
                'last_error': None}
        store.set_setting('feed', feed)
        store.set_setting('feed_error', None)
        return status(store)
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        store.set_setting('feed_error', 'Import rejected; last valid dataset retained.')
        raise ValueError('Invalid feed. Last valid dataset was retained.') from exc


def status(store):
    feed = store.setting('feed', {}) if store else {}
    age = None
    if feed:
        age = (datetime.now(timezone.utc) - datetime.fromisoformat(feed['published_at'])).total_seconds() / 86400
    return {'name': feed.get('name'), 'status': 'unavailable' if not feed else 'stale' if age > 7 else 'current',
            'published_at': feed.get('published_at'), 'imported_at': feed.get('imported_at'),
            'count': len(feed.get('indicators', [])), 'last_error': store.setting('feed_error') if store else None,
            'meaning': 'No match only means not found in this dataset.'}


def matches(store, indicators):
    feed = store.setting('feed', {}) if store else {}
    known = {(r['type'], r['digest']) for r in feed.get('indicators', [])}
    return [i['id'] for i in indicators if (i['type'], hashlib.sha256(i['raw'].encode()).hexdigest()) in known]
