# Changes

### 05/24/2025

- Added support for host:port entries in static_hosts to override global port list per host
- Integrated STARTTLS support for SMTP (e.g. port 587)
- SNI is now correctly set based on the original hostname (if provided)
- Hostnames in static_hosts are resolved to A and AAAA records; all resolved IPs are scanned
- IPv6 scanning is now conditional and fully configurable via enable_ipv6_discovery
- Webhook payload includes original hostname (if applicable)
- Updated README.md to reflect config changes and new usage patterns
- Added test-tls-server.sh script for local testing of discovery functionality
- Improved debug logging and error handling throughout
