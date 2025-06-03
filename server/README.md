# Server Utilities for UltraPKI CertScan

This directory contains server-side utilities for testing and proxying webhook calls in the context of UltraPKI CertScan. Below is a description of each script:

## webhook-proxy.py
A simple HTTP proxy server that receives webhook calls from local agents and forwards them to the UltraPKI Dashboard (`https://cd.ultrapki.com`).

- **Purpose:** Allows local agents to report findings internally without direct internet access. Only the proxy server needs outbound connectivity.
- **Features:**
  - Forwards POST requests to the UltraPKI Dashboard.
  - Returns the remote response to the original client.
  - Handles graceful shutdown on SIGINT.
- **Usage:**
  ```sh
  python3 webhook-proxy.py
  ```

## webhook-server.py
A minimal HTTP server for testing webhook integrations locally.

- **Purpose:** Simulates a webhook endpoint to receive and log incoming requests for development and testing.
- **Features:**
  - Prints received requests (headers and body) to the console.
  - Useful for debugging agent integrations.
- **Usage:**
  ```sh
  python3 webhook-server.py
  ```

## tls-server.sh
A shell script to start a simple HTTPS server for local testing.

- **Purpose:** Provides a TLS-enabled endpoint for testing webhook delivery over HTTPS.
- **Features:**
  - Uses Python's built-in HTTP server with TLS support.
  - Automatically generates `cert.pem` and `key.pem`.
- **Usage:**
  ```sh
  ./tls-server.sh
  ```

---

**Note:** These utilities are intended for development and testing purposes. Do not use them in production environments without proper security review.
