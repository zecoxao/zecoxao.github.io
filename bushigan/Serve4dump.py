#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import http.server, socketserver, os
from urllib.parse import urlparse

HOST = "192.168.1.63"
PORT = 8000
UPLOAD_DIR = os.path.dirname(os.path.abspath(__file__))

class BushiganHandler(http.server.SimpleHTTPRequestHandler):
    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/upload":
            length = int(self.headers.get('Content-Length', 0))
            data = self.rfile.read(length)
            filename = self.headers.get("X-Filename", "dump_corrupt.bin")
            filepath = os.path.join(UPLOAD_DIR, filename)
            with open(filepath, "wb") as f:
                f.write(data)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"OK\n")
            print(f"[+] dump reçu → {filepath} ({len(data)} octets)")
        else:
            super().do_POST()

if __name__ == "__main__":
    os.chdir(UPLOAD_DIR)
    print(f"=== BUSHIGAN DUMP SERVER ===")
    print(f"Serveur : http://{HOST}:{PORT}")
    with socketserver.TCPServer((HOST, PORT), BushiganHandler) as httpd:
        httpd.serve_forever()
