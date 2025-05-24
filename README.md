# UltraPKI Certificate Discovery

A lightweight, daemon-capable certificate discovery and reporting agent written in Go and Python.

This tool acts as an **auto-discovery agent** that scans your entire local IPv4 and (optionally) IPv6 network for TLS-enabled services. It automatically identifies neighbors on the network and inspects known ports for certificates. In addition to dynamic discovery, it also supports scanning explicitly configured static IP addresses and hostnames.

For every discovered service, the agent extracts TLS certificate metadata (issuer, fingerprint, expiration) and sends the result to a central Webhook endpoint. It supports both traditional TLS handshakes and STARTTLS upgrades (e.g., SMTP on port 587).

## Features

* Automatic discovery of network neighbors over IPv4 and optionally IPv6
* Static IP and hostname support with optional per-host port override
* Hostname resolution (A and AAAA records)
* SNI-aware TLS support for accurate certificate retrieval
* Periodic background scanning (daemon mode)
* Webhook delivery with JSON and base64-encoded certificates
* Configurable port list and scan throttle
* PID file and optional log file output
* Configurable debug logging
* Graceful shutdown via SIGINT or SIGTERM
* Native systemd service support

## Configuration

### Example: `config.yaml`

```
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
  - smtp.gmail.com
  - mail.example.com:587
  - 2001:4860:4860::8888
```

* `static_hosts` accepts plain IP addresses, hostnames, or `host:port` entries.
* If a port is provided (e.g., `mail.example.com:587`), only that port is scanned.
* If no port is provided, all ports defined in the `ports` section are used.
* Hostnames are resolved to A and AAAA records; IPv6 is used only if explicitly enabled.

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
Supports multiple IPs per hostname.

## Local TLS Test Server

Use the `test-tls-server.sh` script to simulate a local TLS endpoint.
This will create a self-signed certificate and launch a TLS server on `localhost:4433`.
Add `localhost:4433` to your `static_hosts` in the config file to validate local discovery.

## License

This project is licensed under the GNU General Public License v3.0. See the LICENSE file for details.
