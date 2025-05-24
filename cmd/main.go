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

	"github.com/ultrapki/certscan/config"
	"github.com/ultrapki/certscan/internal/logutil"
	"github.com/ultrapki/certscan/internal/scanner"
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

func main() {

	normalizeFlags()
	configPath := flag.String("config", "config/config.yaml", "Path to configuration file")
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

		// Static Hosts
		// Static Hosts
		for _, hostEntry := range cfg.StaticHosts {
			if scanned[hostEntry] {
				continue
			}

			host, port, hasPort, err := parseStaticHostEntry(hostEntry)
			if err != nil {
				logutil.ErrorLog("Failed to parse static_hosts entry %s: %v", hostEntry, err)
				continue
			}

			ip := net.ParseIP(host)
			if ip != nil {
				if ip.To4() == nil && !cfg.EnableIPv6Discovery {
					logutil.DebugLog("Skipping IPv6 address %s (IPv6 disabled)", host)
					continue
				}

				if hasPort {
					portNum, _ := strconv.Atoi(port)
					logutil.DebugLog("Scanning static IP: %s (port %d only)", host, portNum)
					scanner.ScanAndSend(ip.String(), host, []int{portNum}, cfg.WebhookURL)
				} else {
					logutil.DebugLog("Scanning static IP: %s (all ports)", host)
					scanner.ScanAndSend(ip.String(), host, cfg.Ports, cfg.WebhookURL)
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
					if ip.To4() == nil && !cfg.EnableIPv6Discovery {
						logutil.DebugLog("Skipping resolved IPv6 address %s (IPv6 disabled)", ip)
						continue
					}
					logutil.DebugLog("Scanning resolved IP: %s for hostname %s (port %d)", ip, host, portNum)
					scanner.ScanAndSend(ip.String(), host, []int{portNum}, cfg.WebhookURL)
				}
			} else {
				logutil.DebugLog("Scanning static hostname: %s (all ports)", host)
				scanner.ResolveAndScan(host, cfg.Ports, cfg.WebhookURL, cfg.EnableIPv6Discovery)
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
				ip, _, err := net.ParseCIDR(addr.String())
				if err != nil {
					continue
				}
				ipStr := ip.String()
				if ip.To4() != nil && !scanned[ipStr] {
					logutil.DebugLog("[debug] Scanning interface IP: %s\n", ipStr)
					scanner.ScanAndSend(ipStr, ipStr, cfg.Ports, cfg.WebhookURL)
					scanned[ipStr] = true
					time.Sleep(time.Duration(cfg.ScanThrottleDelayMs) * time.Millisecond)
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
						scanner.ScanAndSend(ip, ip, cfg.Ports, cfg.WebhookURL)
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
