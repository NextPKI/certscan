# UltraPKI Certificate Discovery

A lightweight, daemon-capable certificate discovery and reporting agent written in Go and Python.

This tool acts as an **auto-discovery agent** that scans your entire local IPv4 and (optionally) IPv6 network for TLS-enabled services. It automatically identifies neighbors on the network and inspects known ports for certificates. In addition to dynamic discovery, it also supports scanning explicitly configured static IP addresses, hostnames, and custom port/protocol combinations.

For every discovered service, the agent extracts TLS certificate metadata (issuer, fingerprint, expiration) and sends the result to a central Webhook endpoint. It supports both traditional TLS handshakes and STARTTLS upgrades (e.g., SMTP on port 587). HTTP(S) endpoints are scanned with proper SNI and Host headers, and protocol-specific logic is applied for web and mail services.

## Features

* Automatic discovery of network neighbors over IPv4 and optionally IPv6
* Static IP, hostname, and CIDR support with per-target port/protocol override
* Hostname resolution (A and AAAA records)
* SNI-aware TLS support for accurate certificate retrieval
* HTTP/1.1, HTTP/2, HTTP/3, and STARTTLS (SMTP, IMAP, POP3) protocol support
* Periodic background scanning (daemon mode)
* Webhook delivery with JSON and base64-encoded certificates
* Configurable port list and scan throttle
* PID file and optional log file output
* Configurable debug logging
* Graceful shutdown via SIGINT or SIGTERM
* Native systemd service support

## Configuration

### Example: `config.yaml`

```yaml
webhook_url: "http://localhost:8000/webhook"
ultrapki_token: "" # Optional: UltraPKI dashboard token
#machine_id: "your-custom-machine-id"
scan_interval_seconds: 3600 # For production, use >3600 (1 hour)
scan_throttle_delay_ms: 50
enable_ipv6_discovery: false
#debug: true
ports:
  - 443   # HTTPS
  - 465   # SMTPS (legacy)
  - 587   # SMTP (submission)
  - 993   # IMAPS
  - 995   # POP3S
include_list:
  - target: "192.168.1.10"
  - target: "mail.example.com:993"
    protocol: "imap"
  - target: "10.0.0.0/28"
  - target: "web.example.com"
    protocol: "h2"
  - target: "203.0.113.5:5001"
    protocol: "http1"
exclude_list:
  - 192.168.1.1
  - badhost.example.com
  - 10.0.0.0/28
  - 2001:db8::/32
```

* `include_list` supports hostnames, IPs, host:port, and IPv4 CIDR ranges. Optionally, set `protocol` (http1, h2, h3, smtp, imap, pop3, custom) per entry.
* If `protocol` is set and no port is given, only port 443 is scanned for that entry.
* If `protocol` is set and a port is given, protocol rules are applied for that port.
* If `protocol` is omitted and the port is a typical web port, http1 is assumed.
* `exclude_list` supports hostnames, IPs, and IPv4/IPv6 CIDRs. Any match is skipped, even if included elsewhere.

## Building the Tool

Build the binary with:

```
make
```

The resulting binary will be named `certscan`.

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

## Run as Daemon

```
./certscan -d -c /etc/certscan/config.yaml -l /var/log/certscan.log -p /var/run/certscan.pid
```

## Systemd Integration

Example `certscan.service` file:

```
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

## Python Webhook Server (for Testing)

A basic testing server is provided at `server/test-webhook-server.py`.
It parses incoming POST requests containing base64-encoded DER certificates and displays metadata such as issuer, validity, and fingerprint.
Supports multiple IPs per hostname. If you add new fields to the webhook payload (e.g., protocol, HTTP headers), update the script to print them.

## Local TLS Test Server

Use the `test-tls-server.sh` script to simulate a local TLS endpoint.
This will create a self-signed certificate and launch a TLS server on `localhost:4433`.
Add `localhost:4433` to your `include_list` in the config file to validate local discovery.

## License

This project is licensed under the GNU General Public License v3.0. See the LICENSE file for details.
