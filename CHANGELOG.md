# Changes

### 06/01/2025

- Unified protocol handling via ScanAndSendWithProtocol and protocolHandlers
- Added global WebPorts and SmtpPorts mappings for protocol detection
- ScanAndSend now defaults to http1 for unknown ports
- Refactored getPrimaryIP and getMachineID, moved to shared.go
- Improved documentation and code clarity in scanner.go
- Updated config and test-config.yaml for modern include/exclude usage
- Removed legacy ScanAndSend logic and updated all call sites
- Various bugfixes and maintainability improvements

### 05/31/2025

- Added new configurable values in config.yaml:
  - `concurrency_limit`: Controls the maximum number of concurrent scans (default: 8).
  - `dial_timeout_ms`: Sets the dial timeout for network connections in milliseconds.
  - `http_timeout_ms`: Sets the HTTP request timeout in milliseconds.
  - `webhook_timeout_ms`: Sets the timeout for webhook result submissions in milliseconds.
- Scanning engine now uses a semaphore to enforce the concurrency limit, improving resource control and stability.
- All timeouts are now consistently applied in the scanner logic, allowing for fine-tuned network and webhook performance.
- Improved documentation in config.yaml for all new and existing fields.
- Refactored scanner to use config-driven concurrency and timeout values throughout.

### 05/28/2025

- Major config.yaml documentation overhaul: clearer sectioning, modern examples, and detailed comments for each field.
- Added explicit description for ultrapki_token, clarifying its use for UltraPKI cloud authentication.
- Protocol tagging in include_list now fully supported and documented; protocol rules are applied for custom ports and default to http1 for web ports.
- Improved logic for sending host headers and GET requests for http1/h2/h3 protocols, even on custom ports.
- Exclusion logic and CIDR handling further refined for robust scanning control.
- Various bugfixes and usability improvements for config parsing and scanning logic.

- Config improvements:
  - Renamed `static_hosts` to `include_list` and added `exclude_list` for flexible host/IP management.
  - Added support for IPv4 CIDR ranges in both `include_list` (expands to all IPs) and `exclude_list` (excludes all IPs in the range). IPv6 CIDRs are supported for exclusion only.
  - Backward compatibility: if `static_hosts` is present, a warning is shown and it is used as `include_list` (unless `include_list` is also present).
  - Updated config file examples and documentation for new fields and CIDR usage.

- Scanning logic:
  - All hosts and IPs (including those discovered via network interfaces or expanded from CIDRs) are now checked against `exclude_list` before scanning.
  - Improved exclusion logic: hostnames and all resolved IPs are checked for exclusion, including CIDR matches.
  - Ensured that no IP in the `exclude_list` is scanned, regardless of how it is discovered.

- Machine ID:
  - The `machine_id` can now be set manually in the config file and is prioritized if present.
  - Improved fallback logic for deterministic machine ID generation, closely matching shell script behavior.

- Other:
  - Added and updated config file examples for clarity.
  - Improved debug logging for scanning and exclusion decisions.


### 05/27/2025

- Improved certificate discovery: now attempts both ECDSA and RSA TLS handshakes for each port and submits all unique certificates to the webhook


### 05/26/2025

 - Added CIDR-based IP discovery for all IPv4 interfaces
 - Excluded loopback (127.0.0.0/8) and broadcast (.255) addresses from scan
 - Report now includes full TLS certificate chain
 - UltraPKI dashboard integration added (token-bound access, secure password setup)


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
