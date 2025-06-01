// Command certscan is the entry point for the certificate discovery and scanning service.
//
// It loads configuration, sets up logging, and performs network scanning based on the include and exclude lists.
// The service can run as a background daemon, write logs to a file, and supports IPv4 and optional IPv6 discovery.
//
// Usage flags:
//
//	--config:   Path to configuration file (default: config.yaml)
//	--daemon:   Run as background daemon
//	--logfile:  Optional path to log file
//	--pidfile:  Optional path to PID file
//
// The main scan loop processes include/exclude lists, scans local interfaces, and optionally discovers IPv6 neighbors.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ultrapki/certscan/internal/config"
	"github.com/ultrapki/certscan/internal/logutil"
	"github.com/ultrapki/certscan/internal/scanner"
	"github.com/ultrapki/certscan/internal/shared"
)

func writePIDFile(path string) {
	pid := os.Getpid()
	f, err := os.Create(path)
	if err != nil {
		log.Fatalf("Failed to write PID file: %v", err)
	}
	fmt.Fprintf(f, "%d\n", pid)
	f.Close()
}

func normalizeFlags() {
	aliases := map[string]string{
		"-d": "--daemon",
		"-c": "--config",
		"-l": "--logfile",
		"-p": "--pidfile",
	}

	for i, arg := range os.Args {
		if val, ok := aliases[arg]; ok {
			os.Args[i] = val
		}
	}
}

func parseStaticHostEntry(entry string) (string, string, bool, error) {
	// Try with SplitHostPort directly first (this handles [IPv6]:port and host:port)
	host, port, err := net.SplitHostPort(entry)
	if err == nil {
		return host, port, true, nil
	}

	// Check if it's an unbracketed IPv6 address with no port
	if strings.Count(entry, ":") >= 2 && !strings.Contains(entry, "]") {
		// Likely plain IPv6 without port
		return entry, "", false, nil
	}

	// Any other value is assumed to be a hostname or IPv4 without port
	return entry, "", false, nil
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] != 0 {
			break
		}
	}
}

func isExcluded(host string, excludeList []string) bool {
	ip := net.ParseIP(host)
	// Debug output isExcluded end exit
	for _, ex := range excludeList {
		if strings.EqualFold(host, ex) {
			return true
		}
		// CIDR exclusion (IPv4 and IPv6)
		if _, ipnet, err := net.ParseCIDR(ex); err == nil {
			if ip != nil && ipnet.Contains(ip) {
				return true
			} else {
			}

			// If host is a hostname, resolve and check all IPs
			if ip == nil {
				ips, err := net.LookupIP(host)
				if err == nil {
					for _, resolvedIP := range ips {
						if ipnet.Contains(resolvedIP) {
							return true
						}
					}
				}
			}
		}
	}
	return false
}

func isExplicitlyIncluded(host string, includeList []string) bool {
	for _, entry := range includeList {
		// Only match direct host/IP/host:port entries, not CIDRs
		if _, _, err := net.ParseCIDR(entry); err == nil {
			continue
		}
		if strings.EqualFold(host, entry) {
			return true
		}
	}
	return false
}

func expandIncludeList(includeList []string) []string {
	var expanded []string
	for _, entry := range includeList {
		if _, ipnet, err := net.ParseCIDR(entry); err == nil {
			// Only expand IPv4 CIDRs
			if ipnet.IP.To4() != nil {
				for ip := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
					ipCopy := net.ParseIP(ip.String())
					if ipCopy != nil {
						expanded = append(expanded, ipCopy.String())
					}
				}
				continue
			}
			// IPv6 CIDRs are ignored for inclusion
		}
		expanded = append(expanded, entry)
	}
	return expanded
}

func main() {

	normalizeFlags()
	configPath := flag.String("config", "config.yaml", "Path to configuration file")
	daemonMode := flag.Bool("daemon", false, "Run as background daemon")
	logFile := flag.String("logfile", "", "Optional: path to log file")
	pidFile := flag.String("pidfile", "", "Optional: path to PID file")
	flag.Parse()

	// Optional: write logs to file
	if *logFile != "" {
		f, err := os.OpenFile(*logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatalf("Failed to open log file: %v", err)
		}
		defer f.Close()
		log.SetOutput(f)
	}

	if *pidFile != "" {
		writePIDFile(*pidFile)
	}

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	shared.Config = cfg

	logutil.DebugEnabled = cfg.Debug

	logutil.DebugLog("🚀 Certificate Discovery started")
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-stop
		logutil.DebugLog("🛑 Shutting down gracefully...")
		os.Exit(0)
	}()

	for {
		scanned := make(map[string]bool)

		// Include List
		for _, entry := range cfg.IncludeList {
			hostEntry := entry.Target
			protocol := entry.Protocol

			// Check if entry is a CIDR
			if _, ipnet, err := net.ParseCIDR(hostEntry); err == nil && ipnet.IP.To4() != nil {
				// Expand IPv4 CIDR to all IPs (excluding broadcast)
				broadcast := make(net.IP, len(ipnet.IP.To4()))
				for i := 0; i < len(ipnet.IP.To4()); i++ {
					broadcast[i] = ipnet.IP[i] | ^ipnet.Mask[i]
				}
				broadcastStr := broadcast.String()
				for ip := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
					ipCopy := net.ParseIP(ip.String())
					ipStr := ipCopy.String()
					if ipStr == broadcastStr {
						logutil.DebugLog("[include_cidr] Skipping broadcast IP: %s", ipStr)
						continue
					}
					if isExcluded(ipStr, cfg.ExcludeList) {
						continue
					}
					if !scanned[ipStr] {
						logutil.DebugLog("[include_cidr] Scanning IP %s on ports %v (protocol: %s)", ipStr, cfg.Ports, protocol)
						scanner.ScanAndSendWithProtocol(ipStr, ipStr, cfg.Ports, protocol)
						scanned[ipStr] = true
						time.Sleep(time.Duration(cfg.ScanThrottleDelayMs) * time.Millisecond)
					}
				}
				continue
			}

			// Parse host entry for port and hasPort
			host, port, hasPort, err := parseStaticHostEntry(hostEntry)
			if err != nil {
				logutil.ErrorLog("Failed to parse include_list entry %s: %v", hostEntry, err)
				continue
			}

			logutil.DebugLog("Processing include entry: %s (port: %s, hasPort: %t)", hostEntry, port, hasPort)

			// Only apply exclusion if not explicitly included
			if !isExplicitlyIncluded(hostEntry, flattenIncludeList(cfg.IncludeList)) && (isExcluded(hostEntry, cfg.ExcludeList) || isExcluded(host, cfg.ExcludeList)) {
				logutil.DebugLog("Skipping excluded host: %s", hostEntry)
				continue
			}

			ip := net.ParseIP(host)
			if ip != nil {
				if !isExplicitlyIncluded(hostEntry, flattenIncludeList(cfg.IncludeList)) && isExcluded(ip.String(), cfg.ExcludeList) {
					// logutil.DebugLog("Skipping excluded IP: %s", ip.String())
					continue
				}
				if ip.To4() == nil && !cfg.EnableIPv6Discovery {
					logutil.DebugLog("Skipping IPv6 address %s (IPv6 disabled)", host)
					continue
				}
				if hasPort {
					portNum, _ := strconv.Atoi(port)
					logutil.DebugLog("Scanning static IP: %s (port %d only)", host, portNum)
					scanner.ScanAndSendWithProtocol(ip.String(), host, []int{portNum}, protocol)
				} else {
					logutil.DebugLog("Scanning static IP: %s (all ports)", host)
					scanner.ScanAndSendWithProtocol(ip.String(), host, cfg.Ports, protocol)
				}
				scanned[hostEntry] = true
				time.Sleep(time.Duration(cfg.ScanThrottleDelayMs) * time.Millisecond)
				continue
			}

			// If it's not a direct IP, treat as hostname
			if hasPort {
				portNum, _ := strconv.Atoi(port)
				logutil.DebugLog("Resolving static hostname: %s (port %d only)", host, portNum)
				ips, err := net.LookupIP(host)
				if err != nil || len(ips) == 0 {
					logutil.ErrorLog("Failed to resolve hostname %s: %v", host, err)
					continue
				}
				for _, ip := range ips {
					if !isExplicitlyIncluded(hostEntry, flattenIncludeList(cfg.IncludeList)) && isExcluded(ip.String(), cfg.ExcludeList) {
						logutil.DebugLog("Skipping excluded resolved IP: %s", ip.String())
						continue
					}
					if ip.To4() == nil && !cfg.EnableIPv6Discovery {
						logutil.DebugLog("Skipping resolved IPv6 address %s (IPv6 disabled)", ip)
						continue
					}
					logutil.DebugLog("Scanning resolved IP: %s for hostname %s (port %d), %s", ip, host, portNum, protocol)
					scanner.ScanAndSendWithProtocol(ip.String(), host, []int{portNum}, protocol)
				}
			} else {
				logutil.DebugLog("Scanning static hostname: %s (all ports)", host)
				scanner.ResolveAndScan(host, cfg.Ports)
			}

			scanned[hostEntry] = true
			time.Sleep(time.Duration(cfg.ScanThrottleDelayMs) * time.Millisecond)
		}

		// IPv4 Interfaces
		interfaces, err := net.Interfaces()
		if err != nil {
			logutil.ErrorLog("Error getting interfaces: %v", err)
		}

		for _, iface := range interfaces {
			addrs, _ := iface.Addrs()
			for _, addr := range addrs {
				ip, ipnet, err := net.ParseCIDR(addr.String())
				if err != nil || ip.To4() == nil {
					continue
				}

				// Skip 127.0.0.0/8 networks
				if ip.IsLoopback() || ipnet.IP.IsLoopback() {
					logutil.DebugLog("[cidr] Skipping loopback network: %s", ipnet.String())
					continue
				}

				// 🎯 Calculate broadcast IP
				broadcast := make(net.IP, len(ipnet.IP.To4()))
				for i := 0; i < len(ipnet.IP.To4()); i++ {
					broadcast[i] = ipnet.IP[i] | ^ipnet.Mask[i]
				}
				broadcastStr := broadcast.String()

				// Scan all IPs in range (excluding broadcast)
				for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
					ipCopy := net.ParseIP(ip.String())
					ipStr := ipCopy.String()

					if ipStr == broadcastStr {
						logutil.DebugLog("[cidr] Skipping broadcast IP: %s", ipStr)
						continue
					}

					if isExcluded(ipStr, cfg.ExcludeList) {
						// logutil.DebugLog("[cidr] Skipping excluded IP: %s", ipStr)
						continue
					}

					if !scanned[ipStr] {
						logutil.DebugLog("[cidr] Scanning IP %s on ports %v", ipStr, cfg.Ports)
						scanner.ScanAndSend(ipStr, ipStr, cfg.Ports)
						scanned[ipStr] = true
						time.Sleep(time.Duration(cfg.ScanThrottleDelayMs) * time.Millisecond)
					}
				}
			}
		}

		// IPv6 Nachbarschaft (optional)
		if cfg.EnableIPv6Discovery {
			for _, iface := range interfaces {
				responders, err := scanner.DiscoverIPv6Neighbors(iface.Name)
				if err != nil {
					logutil.DebugLog("[debug] IPv6 discovery failed on %s: %v", iface.Name, err)
					continue
				}
				for _, ip := range responders {
					if !scanned[ip] {
						logutil.DebugLog("[debug] Scanning discovered IPv6 neighbor: %s\n", ip)
						scanner.ScanAndSend(ip, ip, cfg.Ports)
						scanned[ip] = true
						time.Sleep(time.Duration(cfg.ScanThrottleDelayMs) * time.Millisecond)
					}
				}
			}
		}

		if !*daemonMode {
			break
		}

		logutil.DebugLog("✅ Scan cycle complete. Sleeping for %d seconds...\n", cfg.ScanIntervalSeconds)
		time.Sleep(time.Duration(cfg.ScanIntervalSeconds) * time.Second)
	}
}

// Helper to flatten IncludeList to []string for isExplicitlyIncluded
func flattenIncludeList(list []config.IncludeEntry) []string {
	var out []string
	for _, e := range list {
		out = append(out, e.Target)
	}
	return out
}
