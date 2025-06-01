"""
A simple HTTP webhook server for testing certificate scan result delivery.

This script implements a local HTTP server that listens for POST requests containing JSON payloads
with certificate scan results. It prints out details about the received certificates, including
fingerprint, issuer, validity period, and more. The server is intended for local development and
debugging of systems that send scan results via webhooks.

Features:
- Listens on port 8000 by default.
- Accepts POST requests with JSON payloads containing scan results.
- Decodes and parses X.509 certificates from base64 DER format.
- Prints certificate details, skipping CA certificates by default (optional).
- Handles graceful shutdown on SIGINT (Ctrl+C).

Dependencies:
- cryptography

Usage:
    python3 test-webhook-server.py

"""

#!/usr/bin/env python3
import http.server
import socketserver
import json
import base64
import signal
import threading
import http.client
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtensionOID

PORT = 8000

class WebhookHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8')

        try:
            payload = json.loads(body)
            primary_ip = payload.get("primary_ip", "unknown-primary-ip")
            machine_id = payload.get("machine_id", "unknown-machine-id")
            data = payload.get("scan_results", [])

            print("\n📥 Webhook received from %s/%s (%d certificates):" % (primary_ip, machine_id, len(data)))

            for entry in data:
                try:
                    certificates = entry.get("certificates", [])
                    print(f"🔒 Certificates for {entry['ip']}:{entry['port']}")
                    # Display handshake_type, http_headers, and timestamp if present
                    if 'handshake_type' in entry:
                        print(f"    ➤ Handshake:  {entry['handshake_type']}")
                    if 'timestamp' in entry:
                        print(f"    ➤ Timestamp:  {entry['timestamp']}")
                    if 'http_headers' in entry and entry['http_headers']:
                        print(f"    ➤ HTTP Headers:")
                        for k, v in entry['http_headers'].items():
                            print(f"        {k}: {v}")
                    for cert in certificates:
                        der = base64.b64decode(cert)
                        cert = x509.load_der_x509_certificate(der, backend=default_backend())

                        # Uncomment the following lines if you want to skip CA certificates
                        # This is optional and can be used to filter out CA certificates

                        try:
                            bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
                            if bc.ca:
                                continue  # Skip CA certs
                        except x509.ExtensionNotFound:
                            pass  # If extension not found, assume it's a leaf cert

                        fingerprint = cert.fingerprint(hashes.SHA256()).hex()
                        issuer = cert.issuer.rfc4514_string()
                        serial = hex(cert.serial_number)
                        not_before = cert.not_valid_before_utc
                        not_after = cert.not_valid_after_utc

                        if 'hostname' in entry:
                            print(f"    ➤ Hostname:   {entry['hostname']}")
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