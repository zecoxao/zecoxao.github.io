import http.server
import socketserver
import os

PORT = 8000

class NoCacheHandler(http.server.SimpleHTTPRequestHandler):
    def send_response_and_headers(self):
        self.send_header('Cache-Control', 'no-store, must-revalidate')
        self.send_header('Pragma', 'no-cache')
        self.send_header('Expires', '0')

    def end_headers(self):
        self.send_response_and_headers()
        super().end_headers()

class ReuseAddressServer(socketserver.TCPServer):
    allow_reuse_address = True

os.chdir(os.path.dirname(os.path.abspath(__file__)))

with ReuseAddressServer(("", PORT), NoCacheHandler) as httpd:
    print(f"Serving at port {PORT}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.server_close()
