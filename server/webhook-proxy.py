"""
A simple HTTP proxy server for forwarding webhook calls to https://cd.ultrapki.com.

The purpose of this proxy is to allow local agents to send their webhook reports internally to one or more proxy servers without requiring direct internet access. The proxy then forwards the requests to the UltraPKI Dashboard on the internet. This keeps the internal infrastructure isolated, and only the proxy needs internet access.

Features:
- Listens on port 8000 by default.
- Accepts POST requests and forwards them to https://cd.ultrapki.com, including Content-Type, Authorization, and x-ultrapki-machine-id headers.
- Returns the response from https://cd.ultrapki.com to the original client.
- Handles graceful shutdown on SIGINT (Ctrl+C).

Dependencies:
- requests

Usage:
    python3 webhook-proxy.py

"""

#!/usr/bin/env python3
import http.server
import socketserver
import signal
import threading
import http.client
import requests
import logging

PORT = 8000

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

class WebhookHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length)
        target_url = 'https://cd.ultrapki.com' + self.path

        allowed_headers = ["content-type", "authorization", "x-ultrapki-machine-id"]
        headers = {}
        for key in self.headers:
            if key.lower() in allowed_headers:
                headers[key] = self.headers[key]

        logging.debug(f"Received POST {self.path} from {self.client_address[0]} with headers: {{k: v for k, v in headers.items()}}")

        try:
            session = requests.Session()
            adapter = requests.adapters.HTTPAdapter(max_retries=3)
            session.mount('https://', adapter)
            session.mount('http://', adapter)
            resp = session.post(target_url, data=body, headers=headers, verify=True, timeout=10)
            logging.debug(f"Forwarded to {target_url} - Status: {resp.status_code}")
            self.send_response(resp.status_code)
            for k, v in resp.headers.items():
                if k.lower() in ["content-type", "content-length", "date", "server"]:
                    self.send_header(k, v)
            self.end_headers()
            self.wfile.write(resp.content)
        except requests.exceptions.Timeout:
            logging.error(f"Timeout forwarding to {target_url}")
            self.send_response(504)
            self.end_headers()
            self.wfile.write(b'Proxy error: Upstream request timed out')
        except Exception as e:
            logging.error(f"Error forwarding to {target_url}: {e}")
            self.send_response(502)
            self.end_headers()
            self.wfile.write(f'Proxy error: {e}'.encode('utf-8'))


class ReusableTCPServer(socketserver.TCPServer):
    allow_reuse_address = True


def start_server():
    httpd = ReusableTCPServer(("", PORT), WebhookHandler)

    def shutdown_handler(sig, frame):
        print("\n🛑 Shutting down server gracefully...")
        threading.Thread(target=httpd.shutdown).start()
        try:
            conn = http.client.HTTPConnection("localhost", PORT, timeout=1)
            conn.request("POST", "/", body="")
            conn.getresponse()
        except:
            pass  # Swallow errors if connection already closing

    signal.signal(signal.SIGINT, shutdown_handler)

    print(f"🚀 Webhook proxy server listening on port {PORT}")
    try:
        httpd.serve_forever()
    finally:
        print("✅ Server exited cleanly.")

if __name__ == "__main__":
    start_server()