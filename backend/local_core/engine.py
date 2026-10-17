"""Evidence first, deterministic scoring second, redacted presentation last."""
import base64
import hashlib
import re
import uuid
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser
from urllib.parse import urlsplit
from . import feeds

MAX_BYTES = 10 * 1024 * 1024
VERSION = '2026.10.17.1'
VERDICTS = {
    'Dangerous': ('⛔', 'खतरनाक'), 'Suspicious': ('⚠', 'संदिग्ध'),
    'No red flags found': ('✓', 'कोई चेतावनी संकेत नहीं मिला'),
    'Inconclusive': ('?', 'नतीजा स्पष्ट नहीं'), 'Analysis unavailable': ('!', 'जाँच उपलब्ध नहीं'),
}
# group prevents correlated observations from being added repeatedly.
RULES = {
    'credential_request': (35, 'persuasion', 'It asks you to share a password, PIN, or one-time code.', 'यह पासवर्ड, पिन या ओटीपी साझा करने को कहता है।'),
    'pressure': (15, 'pressure', 'It pressures you to act quickly or lose access.', 'यह जल्दी कदम उठाने या खाता बंद होने का डर दिखाता है।'),
    'advance_payment': (40, 'payment', 'It asks for money to claim a prize, job, or reward.', 'यह इनाम या नौकरी पाने के लिए पहले पैसे माँगता है।'),
    'remote_access': (35, 'persuasion', 'It asks you to install a remote-control app.', 'यह आपके फ़ोन या कंप्यूटर को दूर से चलाने वाला ऐप लगाने को कहता है।'),
    'reply_mismatch': (15, 'identity', 'Replies go to a different website than the sender uses.', 'जवाब भेजने का पता, भेजने वाले के पते से अलग है।'),
    'sender_disguise': (30, 'identity', 'The sender address does not match the name or brand it resembles.', 'भेजने वाले का पता उसके नाम या ब्रांड से मेल नहीं खाता।'),
    'link_disguise': (35, 'link', 'A link hides or changes the website it opens.', 'लिंक जिस वेबसाइट पर जाता है, वह दिखाए गए नाम से अलग है।'),
    'executable': (35, 'file', 'This file can install software or run commands.', 'यह फ़ाइल सॉफ़्टवेयर लगा सकती है या कमांड चला सकती है।'),
    'disguised_file': (70, 'file', 'The name looks like a document, but the file can run software.', 'नाम दस्तावेज़ जैसा है, लेकिन यह फ़ाइल सॉफ़्टवेयर चला सकती है।'),
    'type_mismatch': (70, 'file', 'The file contents do not match its document name.', 'फ़ाइल के अंदर का प्रकार उसके दस्तावेज़ वाले नाम से अलग है।'),
    'file_type_mismatch': (25, 'file', 'The file type differs from the type shown by its name.', 'फ़ाइल का प्रकार उसके नाम में दिखाए गए प्रकार से अलग है।'),
    'reputation': (80, 'reputation', 'An offline threat list contains this link or file.', 'ऑफ़लाइन खतरे की सूची में यह लिंक या फ़ाइल मिली है।'),
    'classifier': (15, 'classifier', 'The wording resembles messages flagged by the local text model.', 'स्थानीय भाषा मॉडल को इसका पाठ संदिग्ध संदेशों जैसा लगा।'),
    'auth_failure': (25, 'authentication', 'A trusted receiving server reported a sender check failure.', 'भरोसेमंद मेल सर्वर ने भेजने वाले की जाँच असफल बताई।'),
    'macro_behavior': (60, 'file', 'This document contains commands that may run software.', 'इस दस्तावेज़ में सॉफ़्टवेयर चलाने वाली कमांड मिली हैं।'),
}


def display(value):
    value = str(value)
    value = re.sub(r'(?i)(https?://[^\s<>"#]+)#[^\s<>" ]*', r'\1#[fragment removed]', value)
    value = re.sub(r'(?i)(https?://[^\s<>"?]+)\?[^\s<>" ]*', r'\1?[query removed]', value)
    value = re.sub(r'(?i)(https?://)[^/@\s]+:[^/@\s]+@', r'\1[credentials removed]@', value)
    value = re.sub(r'\b[\w.+-]+@([\w.-]+)\b', r'[address]@\1', value)
    value = re.sub(r'\b\d{6,16}\b', '[number removed]', value)
    value = value.replace('https://', 'hxxps://').replace('http://', 'hxxp://')
    return value.replace('.', '[.]')[:2000]


class TextOnly(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.text, self.links, self.hidden, self.anchor = [], [], 0, None

    def handle_starttag(self, tag, attrs):
        if tag in ('script', 'style', 'iframe', 'object'):
            self.hidden += 1
        if tag == 'a' and not self.hidden:
            self.anchor = [dict(attrs).get('href', ''), '']

    def handle_endtag(self, tag):
        if tag in ('script', 'style', 'iframe', 'object'):
            self.hidden = max(0, self.hidden - 1)
        if tag == 'a' and self.anchor:
            self.links.append(self.anchor)
            self.anchor = None

    def handle_data(self, data):
        if not self.hidden:
            self.text.append(data)
            if self.anchor:
                self.anchor[1] += data


def domain(address):
    return parseaddr(address)[1].rpartition('@')[2].lower()


def authentication(raw_items, trusted_boundary=None):
    """Trust is caller-supplied provenance, NEVER inferred from a header hostname.

    A trusted boundary requires an independently validated exact header index and
    authserv-id. Current public input paths intentionally supply no such assertion.
    """
    results, hops = [], []
    for index, (key, value) in enumerate(raw_items):
        if key.lower() == 'received':
            hops.append({'index': index, 'observation': display(value), 'trust': 'unverified claim'})
        if key.lower() == 'authentication-results':
            service = value.split(';')[0].strip()
            trusted = bool(trusted_boundary and trusted_boundary.get('index') == index and
                           trusted_boundary.get('authserv_id') == service)
            for mechanism in ('spf', 'dkim', 'dmarc'):
                for match in re.finditer(r'\b' + mechanism + r'\s*=\s*(\w+)', value, re.I):
                    results.append({'mechanism': mechanism, 'result': match.group(1).lower(),
                                    'header_index': index, 'authserv_id': display(service),
                                    'trust': 'trusted receiving boundary' if trusted else 'unverified claim'})
    return results, hops


def analyze(kind, content='', filename='', raw=None, store=None, model=None, trusted_boundary=None):
    result = {'schema_version': '1.0', 'analysis_id': str(uuid.uuid4()), 'input_type': kind,
              'created_at': feeds.now(), 'risk_score': None, 'verdict': 'Analysis unavailable',
              'completion': 'unavailable', 'reasons': [], 'action': {}, 'checks': [],
              'technical': {'indicators': [], 'authentication': [], 'received': [], 'files': [], 'rules': []},
              'feeds': feeds.status(store), 'versions': {'rules': VERSION, 'classifier': 'unavailable'},
              'limitations': [], 'external_services_contacted': []}
    checks, technical = result['checks'], result['technical']
    findings, indicators, links, attachments = [], [], [], []
    text = content

    def check(name, state, detail):
        checks.append({'id': name, 'status': state, 'detail': detail})

    def add(rule, evidence):
        weight, group, en, hi = RULES[rule]
        findings.append({'rule_id': rule, 'weight': weight, 'group': group,
                         'evidence_ids': evidence, 'text': {'en': en, 'hi': hi}})

    def indicator(typ, value, source):
        if not value:
            return
        existing = next((i for i in indicators if i['type'] == typ and i['raw'] == value), None)
        if existing:
            if source not in existing['sources']:
                existing['sources'].append(source)
            return existing['id']
        ident = 'ioc-' + str(len(indicators) + 1)
        indicators.append({'id': ident, 'type': typ, 'raw': value, 'sources': [source]})
        return ident

    try:
        if kind not in ('message', 'link', 'filename', 'email', 'file'):
            raise ValueError('Unsupported input type.')
        if len(content) > 100000 or (raw is not None and len(raw) > MAX_BYTES):
            raise ValueError('Input exceeds the size limit.')
        if len(filename) > 1000:
            raise ValueError('Filename exceeds the length limit.')
        if kind in ('email', 'file') and not raw:
            raise ValueError('The file is empty.')
        if kind in ('message', 'link') and not content.strip():
            raise ValueError('Paste some text first.')
        if kind == 'filename' and not filename.strip():
            raise ValueError('Enter a filename first.')
        if kind == 'email':
            if filename.lower().endswith('.msg'):
                raise ValueError('Outlook MSG is not enabled in this local build. Export as EML.')
            if not re.search(br'(?im)^(from|subject|mime-version|received):', raw[:8192]):
                raise ValueError('This does not look like an EML email.')
            msg = BytesParser(policy=policy.default).parsebytes(raw)
            items = [(k, str(v)) for k, v in msg.raw_items()]
            auth, received = authentication(items, trusted_boundary)
            failures = [a for a in auth if a['trust'] == 'trusted receiving boundary' and a['result'] in ('fail', 'softfail')]
            if failures:
                add('auth_failure', ['header:' + str(a['header_index']) for a in failures])
            technical.update(authentication=auth, received=received,
                             headers=[{'name': k, 'value': '[not retained]' if k.lower() == 'subject' else display(v)} for k, v in items
                                      if k.lower() in ('from', 'reply-to', 'subject', 'date', 'authentication-results')])
            check('authentication', 'unavailable', 'Headers preserved as claims; no independently validated receiver boundary. No DNS requests.')
            sender, reply = domain(str(msg.get('From', ''))), domain(str(msg.get('Reply-To', '')))
            indicator('domain', sender, 'header:From')
            indicator('domain', reply, 'header:Reply-To')
            if sender and len(sender) <= 253:
                from forensics.domain_similarity import analyze_domain
                similarity = analyze_domain(sender, parseaddr(str(msg.get('From', '')))[0][:200])
                technical['sender_checks'] = {key: similarity.get(key) for key in ('homograph_suspected', 'lookalike_brand', 'display_name_domain_mismatch')}
                if any(similarity.get(key) for key in ('homograph_suspected', 'lookalike_brand', 'display_name_domain_mismatch')):
                    add('sender_disguise', ['header:From'])
            if sender and reply and sender != reply:
                add('reply_mismatch', ['header:From', 'header:Reply-To'])
            texts = [str(msg.get('Subject', ''))]
            stack, count = [(msg, 0)], 0
            while stack:
                part, depth = stack.pop()
                count += 1
                if count > 100 or depth > 20:
                    raise ValueError('Email exceeds MIME part or nesting limits.')
                if part.defects:
                    check('mime', 'failed', 'Malformed MIME data; some content may not be readable.')
                if part.is_multipart():
                    stack.extend((p, depth + 1) for p in reversed(list(part.iter_parts())))
                    continue
                if part.get_filename() or part.get_content_disposition() == 'attachment':
                    attachments.append((part.get_filename() or 'unnamed', part.get_payload(decode=True) or b''))
                    if len(attachments) > 20:
                        raise ValueError('Email has more than 20 attachments.')
                elif part.get_content_type() in ('text/plain', 'text/html'):
                    value = part.get_content()
                    if part.get_content_type() == 'text/html':
                        parser = TextOnly()
                        parser.feed(value)
                        texts.append(' '.join(parser.text))
                        links.extend(parser.links)
                    else:
                        texts.append(value)
            text = '\n'.join(texts)
            check('email_parse', 'completed', 'Parsed in memory. HTML is never rendered or fetched.')
        if kind in ('filename', 'file'):
            attachments.append((filename, raw))
        optional = {}
        if any(data is not None for _, data in attachments):
            from .optional_files import inspect_batch
            optional, state, detail = inspect_batch(attachments)
            check('optional_file_tools', state, detail)
        for index, (name, data) in enumerate(attachments):
            ref = 'file-' + str(index + 1)
            lowered = name.lower().rstrip(' .')
            ext = lowered.rsplit('.', 1)[-1]
            executable = ext in ('apk', 'exe', 'scr', 'bat', 'cmd', 'ps1', 'js', 'vbs', 'msi', 'com')
            disguised = executable and bool(re.search(r'\.(pdf|docx?|xlsx?|jpe?g|png|txt)\.', lowered))
            if disguised or '\u202e' in name:
                add('disguised_file', [ref])
            elif executable:
                add('executable', [ref])
            entry = {'id': ref, 'filename': display(name), 'size': len(data) if data is not None else None}
            if data is not None:
                from forensics.file_signatures import detect_actual_type
                entry['type'] = detect_actual_type(data)
                entry['sha256'] = hashlib.sha256(data).hexdigest()
                indicator('sha256', entry['sha256'], ref)
                if data.startswith((b'MZ', b'\x7fELF')) and not executable:
                    add('type_mismatch', [ref])
                expected = {'pdf': 'application/pdf', 'png': 'image/png', 'jpg': 'image/jpeg', 'jpeg': 'image/jpeg', 'gif': 'image/gif'}
                if ext in expected and entry['type'] not in (expected[ext], 'application/octet-stream'):
                    add('file_type_mismatch', [ref])
                check(ref, 'completed', 'Static signature and SHA-256 only. No file execution or archive extraction.')
                if ext in ('zip', 'apk', 'doc', 'docx', 'xls', 'xlsx', 'docm', 'xlsm', 'pdf', 'png', 'jpg', 'jpeg'):
                    check(ref + ':deep', 'unavailable', 'Archive contents, macros, OCR and QR are not inspected in the minimal build.')
            else:
                check(ref, 'completed', 'Filename checked without downloading the file.')
                check(ref + ':contents', 'unavailable', 'A name alone cannot establish file safety.')
            technical['files'].append(entry)
            extra = optional.get(name, {})
            if extra:
                entry['optional_checks'] = {'macros': extra.get('macros'), 'image': extra.get('image')}
                macro = extra.get('macro_result', {})
                if macro.get('suspicious') or macro.get('risk_score', 0) >= 50:
                    add('macro_behavior', [ref])
                text += '\n' + extra.get('ocr_text', '')[:100000]
                for url in extra.get('qr_urls', [])[:100]:
                    indicator('url', url, ref + ':qr_code')
                    try:
                        host = urlsplit(url).hostname
                        if host:
                            indicator('domain', host.lower(), ref + ':qr_code')
                    except ValueError:
                        pass
        if len(text) > 100000:
            text = text[:100000]
            check('text_limit', 'failed', 'Text after the first 100,000 characters was not analyzed.')
        for match in re.finditer(r'https?://[^\s<>"\x00-\x1f]+', text, re.I):
            links.append([match.group(0).rstrip('.,;!'), ''])
        if kind == 'link':
            if not re.fullmatch(r'https?://\S+', content.strip(), re.I):
                raise ValueError('Paste one complete http:// or https:// link.')
            check('destination', 'unavailable', 'The website was not visited. Redirects and page content were not checked.')
        for url, shown in links[:200]:
            try:
                parsed = urlsplit(url)
                if parsed.scheme not in ('http', 'https') or not parsed.hostname:
                    continue
                ref = indicator('url', url, 'html_link' if shown else 'message_text')
                indicator('domain', parsed.hostname.lower(), ref)
                if parsed.username or 'xn--' in parsed.hostname or (shown.startswith(('https://', 'http://')) and urlsplit(shown.strip()).hostname != parsed.hostname):
                    add('link_disguise', [ref])
            except ValueError:
                check('url', 'failed', 'A malformed URL could not be inspected.')
        for typ, pattern in [('phone', r'(?<!\w)(?:\+91[ -]?)?[6-9]\d{9}\b'),
                             ('upi', r'\b[\w.-]+@(?:upi|paytm|ybl|ibl|okaxis|okhdfcbank|oksbi|axl)\b'),
                             ('amount', r'(?:₹|Rs\.?|INR)\s*[\d,]+(?:\.\d{1,2})?')]:
            for match in re.finditer(pattern, text, re.I):
                indicator(typ, match.group(0), 'message_text')
        # Generic match descriptions preserve evidence links without storing private bodies.
        evidence = []
        patterns = {
            'credential_request': r'(?is)(?:share|send|tell|enter|verify|भेज|बताएं|बताओ|साझा|bhejo|batao).{0,45}(?:otp|password|pin|ओटीपी|पासवर्ड)|(?:otp|password|pin|ओटीपी).{0,30}(?:भेज|बताएं|share|bhejo)',
            'pressure': r'(?i)urgent|immediately|suspend|expire|within \d+ (?:hour|minute)|तुरंत|अभी|बंद हो|jaldi|turant|band ho',
            'advance_payment': r'(?is)(?:prize|lottery|reward|job|इनाम|लॉटरी|नौकरी|inaam).{0,140}(?:pay|fee|deposit|₹|पैसे|जमा|भुगतान)|(?:pay|fee|deposit|पैसे|जमा).{0,100}(?:prize|lottery|reward|job|इनाम|नौकरी)',
            'remote_access': r'(?i)(?:install|download|लगाएं|डाउनलोड).{0,50}(?:anydesk|teamviewer|remote control)',
        }
        for rule, pattern in patterns.items():
            match = re.search(pattern, text)
            if match and rule == 'credential_request' and re.search(r'(?i)(?:never|do not|don.t|नहीं|मत)\s*$', text[max(0, match.start()-20):match.start()]):
                match = None
            if match:
                ref = 'text:' + rule
                evidence.append({'id': ref, 'description': RULES[rule][2], 'source': 'message_text'})
                add(rule, [ref])
        technical['text_evidence'] = evidence
        check('rules', 'completed', 'Local English, Hindi and Hinglish patterns. Language quality is not independently validated.')
        if model and text:
            try:
                probability = model.predict(text)
                technical['classifier'] = {'probability': round(probability, 4), 'meaning': 'Uncalibrated model output, not overall confidence.'}
                result['versions']['classifier'] = model.version
                check('classifier', 'completed', 'Local TF-IDF + logistic regression; never overrides rules.')
                if probability >= .85:
                    add('classifier', ['model:text'])
            except Exception:
                check('classifier', 'failed', 'Local model could not run.')
        else:
            check('classifier', 'unavailable', 'No validated local model installed. Rules still run.')
        hits = feeds.matches(store, indicators)
        if hits:
            add('reputation', hits)
        check('offline_reputation', 'completed' if result['feeds']['status'] == 'current' else 'unavailable',
              'Local dataset status: ' + result['feeds']['status'] + '. No match is not a safety claim.')
        # Keep only the strongest finding per correlated group, with merged evidence IDs.
        grouped = {}
        for finding in findings:
            prior = grouped.get(finding['group'])
            if prior is None or finding['weight'] > prior['weight']:
                grouped[finding['group']] = finding
            elif prior['rule_id'] == finding['rule_id']:
                prior['evidence_ids'] = list(dict.fromkeys(prior['evidence_ids'] + finding['evidence_ids']))
        ordered = sorted(grouped.values(), key=lambda r: -r['weight'])
        score = min(100, sum(r['weight'] for r in ordered))
        partial = any(c['status'] in ('failed', 'unavailable') for c in checks)
        result.update(risk_score=score, completion='partial' if partial else 'complete',
                      verdict='Dangerous' if score >= 70 else 'Suspicious' if score >= 30 else 'Inconclusive' if partial else 'No red flags found',
                      reasons=ordered[:3])
        technical['rules'] = ordered
        technical['all_rule_matches'] = findings
        technical['indicators'] = [{'id': i['id'], 'type': i['type'], 'display': display(i['raw']),
                                    'sources': i['sources'], 'meaning': 'Observed indicator, not proof of wrongdoing.'} for i in indicators]
        result['limitations'] = [c['detail'] for c in checks if c['status'] in ('unavailable', 'failed')]
    except (ValueError, TypeError, LookupError, RecursionError) as exc:
        result['limitations'] = [str(exc)]
        check('input', 'failed', str(exc))
    danger = result['verdict'] in ('Dangerous', 'Suspicious')
    result['action'] = {
        'en': 'Do not reply, pay, or open files. Contact the person or company using a number you already trust.' if danger else 'Check with the sender using a contact you already trust before paying, sharing details, or opening files.',
        'hi': 'जवाब न दें, पैसे न भेजें और फ़ाइल न खोलें। पहले से भरोसेमंद नंबर पर व्यक्ति या कंपनी से बात करें।' if danger else 'पैसे भेजने, जानकारी देने या फ़ाइल खोलने से पहले, भरोसेमंद संपर्क से भेजने वाले की पुष्टि करें।'}
    result['verdict_label'] = {'en': result['verdict'], 'hi': VERDICTS[result['verdict']][1]}
    result['verdict_icon'] = VERDICTS[result['verdict']][0]
    return result
