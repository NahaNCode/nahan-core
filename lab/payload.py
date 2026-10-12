"""Loopback-only 4 MiB transfer fixture for runtime rate-limit checks."""
from http.server import BaseHTTPRequestHandler, HTTPServer

class Payload(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Length', str(4 * 1024 * 1024))
        self.end_headers()
        try:
            for _ in range(64):
                self.wfile.write(b'x' * 65536)
        except (BrokenPipeError, ConnectionResetError):
            pass

HTTPServer(('127.0.0.1', 38448), Payload).serve_forever()
