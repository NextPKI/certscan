package scanner

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ultrapki/certscan/internal/logutil"
	"github.com/ultrapki/certscan/internal/shared"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"
)

type Payload struct {
	PrimaryIP   string       `json:"primary_ip,omitempty"`
	MachineID   string       `json:"machine_id,omitempty"`
	ScanResults []ScanResult `json:"scan_results"`
}

type ScanResult struct {
	IP           string   `json:"ip"`
	Port         int      `json:"port"`
	Hostname     string   `json:"hostname,omitempty"`
	Certificates []string `json:"certificates,omitempty"`
	Timestamp    int64    `json:"timestamp"`
}

// ScanAndSend tries to connect to IP:port and collect certificate data
func ScanAndSend(ip, hostname string, ports []int) {
	var results []ScanResult
	webhookURL := shared.Config.WebhookURL

	for _, port := range ports {

		if port == 587 { // Special case for SMTP with STARTTLS
			// Debug output for ip, hostname
			logutil.DebugLog("Scanning %s|%s:%d for STARTTLS", ip, hostname, port)
			result, err := scanSMTPStartTLS(ip, hostname, port)
			if err != nil {
				logutil.DebugLog("STARTTLS scan failed: %v", err)
				continue
			}
			// Debug output for successful scan
			logutil.DebugLog("STARTTLS scan successful for %s:%d", ip, port)
			// Debug output result
			logutil.DebugLog("Certificate for %s:%d: %w", ip, port, result)
			sendToWebhook([]ScanResult{*result}, webhookURL)
			continue
		}

		// For other ports, use TLS directly

		address := fmt.Sprintf("[%s]:%d", ip, port)
		dialer := &net.Dialer{Timeout: time.Second}

		conn, err := tls.DialWithDialer(dialer, "tcp", address, &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         hostname,
		})

		if err != nil {
			logutil.DebugLog("Unable to connect to %s: %v", address, err)
			continue
		}

		state := conn.ConnectionState()
		if len(state.PeerCertificates) == 0 {
			conn.Close()
			continue
		}

		logutil.DebugLog("Server Certificates %w", state.PeerCertificates)

		var certs []string
		for _, cert := range state.PeerCertificates {
			certs = append(certs, base64.StdEncoding.EncodeToString(cert.Raw))
		}

		result := ScanResult{
			IP:           ip,
			Port:         port,
			Hostname:     hostname,
			Certificates: certs,
			Timestamp:    time.Now().Unix(),
		}

		results = append(results, result)
		conn.Close()
	}

	if len(results) > 0 {
		sendToWebhook(results, webhookURL)
	}
}

func sendToWebhook(results []ScanResult, url string) {

	payload := Payload{
		PrimaryIP:   getPrimaryIP(),
		MachineID:   getMachineID(),
		ScanResults: results,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		logutil.ErrorLog("Failed to marshal results: %v", err)
		return
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		logutil.ErrorLog("Failed to create request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	if shared.Config.Token != "" {
		req.Header.Set("Authorization", "Bearer "+shared.Config.Token)
		req.Header.Set("x-ultrapki-machine-id", getMachineID())
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		logutil.ErrorLog("Webhook request failed: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		logutil.ErrorLog("Webhook returned status: %d", resp.StatusCode)
		// If 403, it might be an invalid token
		if resp.StatusCode == http.StatusForbidden {
			logutil.ErrorLog("Invalid or missing token for webhook %s", url)
			// Quit the program if token is invalid and ask user to
			// go to https://ultrapki.com/ to get instructions to
			// get a new token
			if shared.Config == nil || shared.Config.Token == "" {
				fmt.Println("\n\nNo token provided.")
				fmt.Println("You can register your system in seconds with the following command:\n")
				fmt.Println("  curl -sSf https://cd.ultrapki.com/sh | sh")
				fmt.Println("\nThis will generate a token for your system and show you how to add it to your config.\n")
				os.Exit(1)
			}
		}
	}
}

func getPrimaryIP() string {
	// No connection will be made. It's just to get the local IP
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "unknown"
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String()
}

func getMachineID() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	hostname += "\n"
	hash := sha256.Sum256([]byte(hostname))
	ret := fmt.Sprintf("%x", hash[:8]) // 8 Byte = 16 Hex-Zeichen
	return ret
}

// ResolveAndScan resolves a hostname (or IP string) and scans each IP
func ResolveAndScan(host string, ports []int) {
	ip := net.ParseIP(host)
	if ip != nil {
		if ip.To4() == nil && !shared.Config.EnableIPv6Discovery {
			logutil.DebugLog("Skipping IPv6 address %s (IPv6 disabled)", ip.String())
			return
		}
		logutil.DebugLog("Scanning resolved IP 2: %s", ip.String())
		ScanAndSend(ip.String(), host, ports)
		return
	}

	ips, err := net.LookupIP(host)
	if err != nil {
		logutil.ErrorLog("Could not resolve %s: %v", host, err)
		return
	}

	logutil.DebugLog("Resolved %s → %v", host, ips)
	for _, ip := range ips {
		if ip.To4() == nil && !shared.Config.EnableIPv6Discovery {
			logutil.DebugLog("Skipping IPv6 address %s (IPv6 disabled)", ip.String())
			continue
		}
		// Debug output for each resolved IP
		logutil.DebugLog("Scanning resolved IP 1: %s", ip.String())
		ScanAndSend(ip.String(), host, ports)
	}
}

// DiscoverIPv6Neighbors sends an ICMPv6 multicast echo to ff02::1 on the given interface
// and returns a list of responding IP addresses (as strings).
func DiscoverIPv6Neighbors(ifaceName string) ([]string, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("interface not found: %w", err)
	}

	conn, err := icmp.ListenPacket("udp6", fmt.Sprintf("%%%s", iface.Name))
	if err != nil {
		return nil, fmt.Errorf("failed to listen for ICMPv6: %w", err)
	}
	defer conn.Close()

	dst := &net.UDPAddr{
		IP:   net.ParseIP("ff02::1"),
		Zone: iface.Name,
	}

	echo := icmp.Message{
		Type: ipv6.ICMPTypeEchoRequest,
		Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  1,
			Data: []byte("certscan"),
		},
	}

	msgBytes, err := echo.Marshal(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal echo request: %w", err)
	}

	if _, err := conn.WriteTo(msgBytes, dst); err != nil {
		return nil, fmt.Errorf("failed to send echo request: %w", err)
	}

	conn.SetReadDeadline(time.Now().Add(3 * time.Second))

	var responders []string
	for {
		buf := make([]byte, 1500)
		n, peer, err := conn.ReadFrom(buf)
		if err != nil {
			break // timeout or done
		}

		msg, err := icmp.ParseMessage(58, buf[:n]) // 58 = ICMPv6
		if err != nil {
			continue
		}

		if msg.Type == ipv6.ICMPTypeEchoReply {
			responders = append(responders, peer.(*net.UDPAddr).IP.String())
		}
	}

	return responders, nil
}

func scanSMTPStartTLS(ip, hostname string, port int) (*ScanResult, error) {
	address := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		return nil, fmt.Errorf("tcp dial failed: %w", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)
	_, err = reader.ReadString('\n') // read greeting
	if err != nil {
		return nil, fmt.Errorf("smtp greeting failed: %w", err)
	}

	fmt.Fprintf(conn, "EHLO certscan\r\n")
	lines := []string{}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("EHLO read failed: %w", err)
		}
		lines = append(lines, line)
		if !strings.HasPrefix(line, "250-") {
			break
		}
	}

	supportsStartTLS := false
	for _, l := range lines {
		if strings.Contains(strings.ToUpper(l), "STARTTLS") {
			supportsStartTLS = true
			break
		}
	}
	if !supportsStartTLS {
		return nil, fmt.Errorf("STARTTLS not supported on %s", ip)
	}

	fmt.Fprintf(conn, "STARTTLS\r\n")
	line, err := reader.ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "220") {
		return nil, fmt.Errorf("STARTTLS failed: %v", line)
	}

	// Upgrade connection
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         hostname,
		InsecureSkipVerify: true,
	})
	err = tlsConn.Handshake()
	if err != nil {
		return nil, fmt.Errorf("TLS handshake failed: %w", err)
	}
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no cert returned")
	}

	var certs []string
	for _, cert := range state.PeerCertificates {
		certs = append(certs, base64.StdEncoding.EncodeToString(cert.Raw))
	}

	return &ScanResult{
		IP:           ip,
		Port:         port,
		Hostname:     hostname,
		Certificates: certs,
		Timestamp:    time.Now().Unix(),
	}, nil
}
