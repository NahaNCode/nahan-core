"""Isolated NahaN compatibility API. Not connected to production accounts."""
import hashlib
import hmac
import json
import os
import sqlite3
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlsplit

DB = os.environ.get('LAB_DB', '/data/lab.sqlite')
KEY = os.environ['LAB_API_KEY']
USER = os.environ['LAB_USER_UUID']
NODE = 900001

def connect():
    db = sqlite3.connect(DB)
    db.execute('PRAGMA journal_mode=WAL')
    return db

def initialize():
    with connect() as db:
        db.executescript('''
          CREATE TABLE IF NOT EXISTS nodes (
            id INTEGER PRIMARY KEY, config TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1);
          CREATE TABLE IF NOT EXISTS receipts (
            node_id INTEGER NOT NULL, report_id TEXT NOT NULL, digest TEXT NOT NULL,
            received INTEGER NOT NULL, PRIMARY KEY(node_id,report_id));
          CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY, uuid TEXT NOT NULL, expires INTEGER NOT NULL,
            quota INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0,
            speed INTEGER NOT NULL, iplimit INTEGER NOT NULL);
          CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY, kind TEXT NOT NULL, received INTEGER NOT NULL,
            body TEXT NOT NULL);
        ''')
        db.execute('INSERT OR IGNORE INTO users VALUES (1,?,?,?,0,20,2)',
                   (USER, int(time.time()) + 86400 * 7, 1024 ** 3))
        config = {'server': {'type': 'Vless', 'listeningport': '38443',
            'listenip': '127.0.0.1', 'address': '127.0.0.1',
            'security': 'none', 'certmode': 'none', 'sniffing': False,
            'networkSettings': {'transport': 'ws', 'path': '/nahan-lab'},
            'socketSettings': {}, 'securitySettings': {}, 'speedlimit': 100},
            'relay': False, 'rules': []}
        db.execute('INSERT OR IGNORE INTO nodes(id,config) VALUES (?,?)', (NODE, json.dumps(config)))

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass  # API keys in query strings must not reach access logs.

    def respond(self, status, body):
        data = json.dumps(body, separators=(',', ':')).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def route(self):
        parsed = urlsplit(self.path)
        key = parse_qs(parsed.query).get('key', [''])[0]
        if not hmac.compare_digest(key, KEY):
            self.respond(403, {'error': 'unauthorized'})
            return None
        pieces = parsed.path.strip('/').split('/')
        if len(pieces) != 3 or pieces[0] != 'api' or pieces[2] != str(NODE):
            self.respond(404, {'error': 'unknown lab node'})
            return None
        with connect() as db:
            node = db.execute('SELECT enabled FROM nodes WHERE id=?', (NODE,)).fetchone()
        if node is None or not node[0]:
            self.respond(403, {'error': 'node disabled'})
            return None
        return pieces[1]

    def do_GET(self):
        route = self.route()
        if route is None:
            return
        if route == 'server':
            with connect() as db:
                result = json.loads(db.execute('SELECT config FROM nodes WHERE id=?', (NODE,)).fetchone()[0])
        elif route == 'subscriptions':
            with connect() as db:
                users = db.execute('SELECT id,uuid,speed,iplimit FROM users '
                    'WHERE expires>? AND used<quota', (int(time.time()),)).fetchall()
            result = {'subscriptions': [{'id': r[0], 'uuid': r[1],
                'email': 'lab-1@nahan.invalid', 'passwd': r[1],
                'speedlimit': r[2], 'iplimit': r[3], 'ipcount': 0} for r in users]}
        else:
            self.respond(404, {'error': 'unknown resource'})
            return
        etag = '"' + hashlib.sha256(json.dumps(result, sort_keys=True).encode()).hexdigest() + '"'
        if self.headers.get('If-None-Match') == etag:
            self.send_response(304)
            self.end_headers()
            return
        data = json.dumps(result).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('ETag', etag)
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        route = self.route()
        if route is None:
            return
        if route not in ('traffic', 'onlineip'):
            self.respond(404, {'error': 'unknown report'})
            return
        try:
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 < length <= 65536:
                raise ValueError()
            body = json.loads(self.rfile.read(length))
            records = body['data']
            if not isinstance(records, list) or len(records) > 100:
                raise ValueError()
            for r in records:
                if r['subscription_id'] != 1:
                    raise ValueError()
                if route == 'traffic' and any(type(r[k]) is not int or r[k] < 0 for k in ('u', 'd')):
                    raise ValueError()
                if route == 'onlineip' and not isinstance(r['ip'], str):
                    raise ValueError()
        except (ValueError, KeyError, TypeError):
            self.respond(400, {'error': 'invalid report'})
            return
        with connect() as db:
            report_id = self.headers.get('Idempotency-Key')
            if report_id:
                if len(report_id) > 128:
                    self.respond(400, {'error': 'invalid report ID'})
                    return
                digest = hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()
                db.execute('BEGIN IMMEDIATE')
                previous = db.execute('SELECT digest FROM receipts WHERE node_id=? AND report_id=?',
                    (NODE, report_id)).fetchone()
                if previous:
                    self.respond(200 if previous[0] == digest else 409,
                        {'ret': 1 if previous[0] == digest else 0, 'duplicate': previous[0] == digest})
                    return
                db.execute('INSERT INTO receipts VALUES (?,?,?,?)', (NODE, report_id, digest, int(time.time())))
            db.execute('INSERT INTO reports(kind,received,body) VALUES (?,?,?)',
                       (route, int(time.time()), json.dumps(body)))
            if route == 'traffic':
                for r in records:
                    db.execute('UPDATE users SET used=used+? WHERE id=1', (r['u'] + r['d'],))
        self.respond(200, {'ret': 1, 'data': []})

if __name__ == '__main__':
    initialize()
    HTTPServer(('127.0.0.1', 38440), Handler).serve_forever()
