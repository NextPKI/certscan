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

import http.server
import socketserver
import json
import base64
import signal
import threading
import http.client
import logging
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtensionOID

PORT = 8000

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

class WebhookHandler(http.server.BaseHTTPRequestHandler):
    """Handles incoming POST requests containing certificate scan results."""
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8')

        try:
            payload = json.loads(body)
            primary_ip = payload.get("primary_ip", "unknown-primary-ip")
            machine_id = payload.get("machine_id", "unknown-machine-id")
            data = payload.get("scan_results", [])

            logging.info(f"Webhook received from {primary_ip}/{machine_id} ({len(data)} certificates)")

            for entry in data:
                try:
                    certificates = entry.get("certificates", [])
                    logging.info(f"Certificates for {entry['ip']}:{entry['port']}")
                    # Display handshake_type, http_headers, and timestamp if present
                    if 'handshake_type' in entry:
                        logging.info(f"    Handshake:  {entry['handshake_type']}")
                    if 'timestamp' in entry:
                        logging.info(f"    Timestamp:  {entry['timestamp']}")
                    if 'http_headers' in entry and entry['http_headers']:
                        logging.info(f"    HTTP Headers:")
                        for k, v in entry['http_headers'].items():
                            logging.info(f"        {k}: {v}")
                    for cert in certificates:
                        der = base64.b64decode(cert)
                        cert = x509.load_der_x509_certificate(der, backend=default_backend())
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
                            logging.info(f"    Hostname:   {entry['hostname']}")
                        logging.info(f"    Serial:     {serial}")
                        logging.info(f"    Fingerprint: {fingerprint[:64]}")
                        logging.info(f"    Valid From:  {not_before}")
                        logging.info(f"    Valid Until: {not_after}")
                        logging.info(f"    Issuer:      {issuer}")
                except Exception as cert_err:
                    logging.warning(f"Error parsing cert from {entry.get('ip')}:{entry.get('port')}: {cert_err}")
        except Exception as parse_err:
            logging.error(f"Invalid payload: {parse_err}")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'OK')

class ReusableTCPServer(socketserver.TCPServer):
    allow_reuse_address = True

def start_server():
    """Starts the HTTP server and handles graceful shutdown."""
    httpd = ReusableTCPServer(("", PORT), WebhookHandler)
    def shutdown_handler(sig, frame):
        logging.info("Shutting down server gracefully...")
        threading.Thread(target=httpd.shutdown).start()
        try:
            conn = http.client.HTTPConnection("localhost", PORT, timeout=1)
            conn.request("POST", "/", body="")
            conn.getresponse()
        except:
            pass  # Swallow errors if connection already closing
    signal.signal(signal.SIGINT, shutdown_handler)
    logging.info(f"Webhook server listening on port {PORT}")
    try:
        httpd.serve_forever()
    finally:
        logging.info("Server exited cleanly.")

if __name__ == "__main__":
    start_server()