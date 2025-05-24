#!/usr/bin/env python3
import http.server
import socketserver
import json
import base64
import hashlib
import signal
import sys
import threading
import http.client
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

PORT = 8000

class WebhookHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8')

        try:
            data = json.loads(body)
            print("\n📥 Webhook received (%d certificates):" % len(data))

            for entry in data:
                try:
                    der = base64.b64decode(entry["cert_pem"])
                    cert = x509.load_der_x509_certificate(der, backend=default_backend())

                    fingerprint = cert.fingerprint(hashes.SHA256()).hex()
                    issuer = cert.issuer.rfc4514_string()
                    serial = hex(cert.serial_number)
                    not_before = cert.not_valid_before
                    not_after = cert.not_valid_after

                    print(f"🔒 Certificate for {entry['ip']}:{entry['port']}")
                    print(f"    ➤ Serial:     {serial}")
                    print(f"    ➤ Fingerprint: {fingerprint[:64]}")
                    print(f"    ➤ Valid From:  {not_before}")
                    print(f"    ➤ Valid Until: {not_after}")
                    print(f"    ➤ Issuer:      {issuer}")
                    print("")

                except Exception as cert_err:
                    print(f"⚠️  Error parsing cert from {entry.get('ip')}:{entry.get('port')}: {cert_err}")

        except Exception as parse_err:
            print(f"❌ Invalid payload: {parse_err}")

        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'OK')


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

    print(f"🚀 Webhook server listening on port {PORT}")
    try:
        httpd.serve_forever()
    finally:
        print("✅ Server exited cleanly.")

if __name__ == "__main__":
    start_server()