# Certificate Discovery

A lightweight, daemon-capable certificate discovery and reporting tool written in Go and Python.

This project scans all available local IPv4 and optionally IPv6 interfaces for TLS-enabled services (HTTPS, SMTPS, IMAPS, etc.), extracts the remote certificate, and sends essential information (issuer, fingerprint, expiration) via Webhook to a central receiver.

## Features

- ✅ IPv4 and optional IPv6 scanning
- ✅ Periodic background scanning (daemon mode)
- ✅ Webhook delivery with JSON + base64 certificate
- ✅ Configurable port list and scan throttle
- ✅ Static host support (manual IPs or hostnames)
- ✅ PID file and optional log file output
- ✅ Debug logging controlled via config
- ✅ Clean shutdown via `SIGINT` or `SIGTERM`
- ✅ Systemd service integration

---

## Configuration

### Example: `config.yaml`

```yaml
webhook_url: "http://localhost:8000/webhook"
scan_interval_seconds: 30
scan_throttle_delay_ms: 50
ipv6_throttle_per_minute: 10
enable_ipv6_discovery: true
debug: true

ports:
  - 443
  - 4433
  - 465
  - 587
  - 993
  - 995
  - 8443

static_hosts:
  - 127.0.0.1
  - localhost
```

---

## Building the Tool

You can build the binary using:

```bash
make
```

Or rebuild it cleanly:

```bash
make remake
```

The compiled binary will be named `certscan` and placed in the current directory.

---

## CLI Usage

```
Usage:
  ./certscan --config=config.yaml [--daemon] [--logfile=...] [--pidfile=...]

Short flags:
  -c = --config
  -d = --daemon
  -l = --logfile
  -p = --pidfile
```

---

## Run as Daemon

```bash
./certscan -d -c /etc/certscan/config.yaml -l /var/log/certscan.log -p /var/run/certscan.pid
```

---

## Systemd Integration

Example `certscan.service` file:

```ini
[Unit]
Description=Certificate Discovery Daemon
After=network.target

[Service]
ExecStart=/usr/local/bin/certscan --daemon --config=/etc/certscan/config.yaml --logfile=/var/log/certscan.log --pidfile=/var/run/certscan.pid
Restart=on-failure
User=certscan
Group=certscan

[Install]
WantedBy=multi-user.target
```

---

## Python Webhook Server (for testing)

A simple test server is provided in `server/test-webhook-server.py`.  
It parses POSTed base64 DER certificates and prints key metadata (issuer, validity, fingerprint).

---

## License

This project is licensed under the [GNU General Public License v3.0](LICENSE).
