import base64
import http.client
import json
import socket
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from local_core.engine import analyze, authentication, MAX_BYTES
from local_core.store import Store
from local_core.feeds import import_feed, status
from local_app import Server


class OfflineTests(unittest.TestCase):
    def test_demo_corpus(self):
        rows=json.loads((Path(__file__).resolve().parents[2]/'docs/fixtures/demo.json').read_text(encoding='utf-8'))
        for row in rows:
            with self.subTest(row['id']):
                raw=row.get('content','').encode() if row['input_type']=='email' else None
                r=analyze(row['input_type'],row.get('content','') if raw is None else '',row.get('filename',''),raw)
                self.assertEqual(r['verdict'],row['expected'])
                self.assertNotEqual(r['verdict'],'Safe')

    def test_forged_authentication(self):
        items=[('Received','from x by mx.google.com'),('Authentication-Results','mx.google.com; spf=pass; dkim=fail; dmarc=pass'),('Received','forged older hop')]
        auth,hops=authentication(items)
        self.assertTrue(all(a['trust']=='unverified claim' for a in auth))
        self.assertEqual([h['index'] for h in hops],[0,2])
        trusted,_=authentication(items,{'index':1,'authserv_id':'mx.google.com'})
        self.assertTrue(all(a['trust']=='trusted receiving boundary' for a in trusted))

    def test_missing_and_partial(self):
        r=analyze('message','');self.assertIsNone(r['risk_score']);self.assertEqual(r['verdict'],'Analysis unavailable')
        r=analyze('message','See you tomorrow.');self.assertEqual(r['verdict'],'Inconclusive')
        self.assertEqual(r['completion'],'partial')

    def test_no_network_and_html(self):
        raw=b'From: a@example.com\nSubject: test\nContent-Type: text/html\n\n<script>fetch("https://tracker.example")</script><img src="https://tracker.example/pixel"><a href="https://evil.example">https://bank.example</a>'
        with patch.object(socket.socket,'connect',side_effect=AssertionError('Unexpected network')),patch('socket.getaddrinfo',side_effect=AssertionError('Unexpected DNS')):
            r=analyze('email',filename='test.eml',raw=raw)
        self.assertEqual(r['verdict'],'Suspicious')
        self.assertEqual(r['external_services_contacted'],[])
        self.assertNotIn('<script>',json.dumps(r))
        self.assertNotIn('tracker.example',json.dumps(r))

    def test_masking_after_matching(self):
        with tempfile.TemporaryDirectory() as d:
            store=Store(d)
            from local_core.feeds import now
            url='https://bad.example/pay?token=secret123456'
            import_feed(store,{'license_accepted':True,'published_at':now(),'indicators':[{'type':'url','value':url}]})
            r=analyze('message',url,store=store)
            self.assertEqual(r['verdict'],'Dangerous')
            self.assertNotIn('secret123456',json.dumps(r))
            store.save(r);self.assertNotIn('secret123456',store.path.read_bytes().decode(errors='ignore'))

    def test_file_limits_and_signatures(self):
        r=analyze('file',filename='invoice.pdf',raw=b'MZ'+b'0'*20)
        self.assertEqual(r['verdict'],'Dangerous')
        self.assertEqual(analyze('file',filename='x',raw=b'a'*(MAX_BYTES+1))['verdict'],'Analysis unavailable')
        self.assertEqual(analyze('email',filename='x.eml',raw=b'not an email')['verdict'],'Analysis unavailable')

    def test_malformed_mime(self):
        r=analyze('email',filename='x.eml',raw=b'From: a@example.com\nContent-Type: multipart/mixed; boundary=missing\n\ninvalid')
        self.assertTrue(any(c['status']=='failed' for c in r['checks']))
        self.assertNotEqual(r['verdict'],'No red flags found')

    def test_feed_stale_and_failed_update(self):
        with tempfile.TemporaryDirectory() as d:
            s=Store(d);import_feed(s,{'license_accepted':True,'published_at':'2020-01-01T00:00:00+00:00','indicators':[{'type':'domain','value':'bad.example'}]})
            self.assertEqual(status(s)['status'],'stale')
            with self.assertRaises(ValueError):import_feed(s,{'indicators':[]})
            self.assertEqual(status(s)['count'],1)
            self.assertIsNotNone(status(s)['last_error'])

    def test_no_duplicate_rule_weight(self):
        r=analyze('message','Urgent immediately urgent share your password share your OTP')
        self.assertEqual(r['risk_score'],50)
        self.assertLessEqual(len(r['reasons']),3)

    def test_warning_is_not_a_credential_request(self):
        r=analyze('message','Never share your password or OTP with anyone.')
        self.assertFalse(any(x['rule_id']=='credential_request' for x in r['technical']['rules']))

    def test_optional_file_worker_failure_keeps_basic_evidence(self):
        with patch('local_core.optional_files.inspect_batch',return_value=({},'failed','Worker timed out.')):
            r=analyze('file',filename='invoice.pdf',raw=b'MZ1234')
        self.assertEqual(r['verdict'],'Dangerous')
        self.assertEqual(r['completion'],'partial')
        self.assertTrue(any(c['id']=='optional_file_tools' and c['status']=='failed' for c in r['checks']))


class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory();cls.server=Server(('127.0.0.1',0),cls.temp.name,cls.temp.name)
        cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True);cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown();cls.server.server_close();cls.thread.join();cls.temp.cleanup()

    def request(self,path,body=None,headers=None,method=None):
        c=http.client.HTTPConnection('127.0.0.1',self.server.server_port)
        h={'Content-Type':'application/json'};h.update(headers or {})
        c.request(method or ('POST' if body is not None else 'GET'),path,json.dumps(body) if body is not None else None,h)
        r=c.getresponse();status=r.status;heads=dict(r.getheaders());data=json.loads(r.read());c.close();return status,heads,data

    def test_unauthorized(self):
        self.assertEqual(self.request('/api/history')[0],401)
        self.assertEqual(self.request('/health',headers={'Host':'evil.example'})[0],403)
        self.assertEqual(self.request('/health',headers={'Origin':'https://evil.example'})[0],403)
        self.assertEqual(self.request('/api/unlock',{'code':'wrong'})[0],403)

    def test_pair_and_cached_report(self):
        origin='chrome-extension://'+'a'*32
        status,_,data=self.request('/api/pair',{'code':self.server.code},{'Origin':origin})
        self.assertEqual(status,200);headers={'Origin':origin,'Authorization':'Bearer '+data['token']}
        status,_,r=self.request('/api/analyze',{'input_type':'message','content':'send your OTP immediately','gmail_message_id':'abcdef12345678'},headers)
        self.assertEqual(status,200);self.assertEqual(r['gmail_message_id'],'abcdef12345678')
        status,_,cached=self.request('/api/analyses/'+r['analysis_id'],headers=headers)
        self.assertEqual(cached,r)
        self.assertEqual(self.request('/api/history',headers={**headers,'Origin':'chrome-extension://'+'b'*32})[0],403)

    def test_unlock_and_schema(self):
        status,headers,_=self.request('/api/unlock',{'code':self.server.code})
        self.assertEqual(status,200);cookie=headers['Set-Cookie'].split(';')[0]
        self.assertEqual(self.request('/api/analyze',{'input_type':'message','content':{}},{'Cookie':cookie})[0],400)


if __name__=='__main__':unittest.main()
