import importlib
import json
import os
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import HTTPServer

class PanelTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        os.environ.update(LAB_DB=cls.directory.name + '/lab.sqlite',
            LAB_API_KEY='test-key', LAB_USER_UUID='11111111-1111-4111-8111-111111111111')
        cls.panel = importlib.import_module('panel')
        cls.panel.initialize()
        cls.server = HTTPServer(('127.0.0.1', 0), cls.panel.Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.thread.join()
        cls.server.server_close()
        cls.directory.cleanup()

    def request(self, resource, data=None, key='test-key', report_id=None):
        url = f'http://127.0.0.1:{self.server.server_port}/api/{resource}/900001?key={key}'
        return urllib.request.urlopen(urllib.request.Request(url,
            data=None if data is None else json.dumps(data).encode(),
            headers={} if report_id is None else {'Idempotency-Key': report_id}), timeout=2)

    def test_idempotency(self):
        body = {'data': [{'subscription_id': 1, 'u': 10, 'd': 20}]}
        with self.panel.connect() as db:
            before = db.execute('SELECT used FROM users').fetchone()[0]
        self.request('traffic', body, report_id='report-1').close()
        duplicate = json.load(self.request('traffic', body, report_id='report-1'))
        self.assertTrue(duplicate['duplicate'])
        with self.panel.connect() as db:
            self.assertEqual(db.execute('SELECT used FROM users').fetchone()[0], before + 30)
        body['data'][0]['u'] = 99
        with self.assertRaises(urllib.error.HTTPError) as error:
            self.request('traffic', body, report_id='report-1')
        self.assertEqual(error.exception.code, 409)
        error.exception.close()

    def test_auth(self):
        with self.assertRaises(urllib.error.HTTPError) as error:
            self.request('server', key='wrong')
        self.assertEqual(error.exception.code, 403)
        error.exception.close()

    def test_lifecycle(self):
        with self.panel.connect() as db:
            db.execute('UPDATE users SET used=0,expires=?', (int(time.time()) + 3600,))
        self.assertEqual(len(json.load(self.request('subscriptions'))['subscriptions']), 1)
        self.request('traffic', {'data': [{'subscription_id': 1, 'u': 100, 'd': 200}]}).close()
        with self.panel.connect() as db:
            self.assertEqual(db.execute('SELECT used FROM users').fetchone()[0], 300)
            db.execute('UPDATE users SET expires=?', (int(time.time()) - 1,))
        self.assertEqual(json.load(self.request('subscriptions'))['subscriptions'], [])
        with self.panel.connect() as db:
            db.execute('UPDATE users SET expires=?,used=quota', (int(time.time()) + 3600,))
        self.assertEqual(json.load(self.request('subscriptions'))['subscriptions'], [])

    def test_invalid_report(self):
        with self.assertRaises(urllib.error.HTTPError) as error:
            self.request('traffic', {'data': [{'subscription_id': 1, 'u': -1, 'd': 0}]})
        self.assertEqual(error.exception.code, 400)
        error.exception.close()

if __name__ == '__main__':
    unittest.main()
