// smtp.go provides the SMTP STARTTLS scan logic and protocol handler for UltraPKI.
// It implements certificate extraction for SMTP services supporting STARTTLS.
// smtp.go: SMTP STARTTLS scan logic and handler
package scanner

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/ultrapki/certscan/internal/logutil"
	"github.com/ultrapki/certscan/internal/shared"
)

// scanSMTPStartTLS connects to an SMTP server, upgrades to TLS using STARTTLS, and extracts certificates.
// Returns a ScanResult with certificate data or an error.
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

// smtpProtocolHandler is a ProtocolHandler for SMTP STARTTLS scanning.
// It sends results to the webhook and returns true if handled.
func smtpProtocolHandler(ip, hostname string, port int) bool {
	result, err := scanSMTPStartTLS(ip, hostname, port)
	if err != nil {
		logutil.DebugLog("STARTTLS scan failed: %v", err)
		return true // handled, but failed
	}
	logutil.DebugLog("STARTTLS scan successful for %s:%d", ip, port)
	logutil.DebugLog("Certificate for %s:%d: %w", ip, port, result)
	// Filter certificates before sending to webhook
	excludeCerts := shared.Config.ExcludeCerts
	result.Certificates = filterCerts(decodeBase64Certs(result.Certificates), excludeCerts)
	sendToWebhook([]ScanResult{*result}, shared.Config.WebhookURL)
	return true
}
