package scanner

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/ultrapki/certscan/internal/logutil"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"
)

type ScanResult struct {
	IP        string `json:"ip"`
	Port      int    `json:"port"`
	CertPEM   string `json:"cert_pem"`
	NotBefore int64  `json:"not_before"`
	NotAfter  int64  `json:"not_after"`
	Timestamp int64  `json:"timestamp"`
}

func ScanAndSend(ip string, ports []int, webhookURL string) {
	var results []ScanResult
	for _, port := range ports {
		address := fmt.Sprintf("[%s]:%d", ip, port)
		dialer := &net.Dialer{
			Timeout: 5 * time.Second,
		}

		conn, err := tls.DialWithDialer(dialer, "tcp", address, &tls.Config{
			InsecureSkipVerify: true,
		})
		if err != nil {
			logutil.DebugLog("[debug] Unable to connect to %s: %v", address, err)
			continue
		}

		state := conn.ConnectionState()
		if len(state.PeerCertificates) == 0 {
			conn.Close()
			continue
		}

		cert := state.PeerCertificates[0]
		result := ScanResult{
			IP:        ip,
			Port:      port,
			CertPEM:   base64.StdEncoding.EncodeToString(cert.Raw),
			NotBefore: cert.NotBefore.Unix(),
			NotAfter:  cert.NotAfter.Unix(),
			Timestamp: time.Now().Unix(),
		}

		results = append(results, result)
		conn.Close()
	}

	if len(results) > 0 {
		sendToWebhook(results, webhookURL)
	}
}

func sendToWebhook(results []ScanResult, url string) {
	jsonData, err := json.Marshal(results)
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

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		logutil.ErrorLog("Webhook request failed: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		logutil.ErrorLog("Webhook returned status: %d", resp.StatusCode)
	}
}

// DiscoverIPv6Neighbors sends ICMPv6 Echo to ff02::1 and collects responders
func DiscoverIPv6Neighbors(ifaceName string) ([]string, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, err
	}

	c, err := icmp.ListenPacket("udp6", fmt.Sprintf("%%%s", iface.Name))
	if err != nil {
		return nil, err
	}
	defer c.Close()

	dst := &net.UDPAddr{
		IP:   net.ParseIP("ff02::1"),
		Zone: iface.Name,
	}

	echo := icmp.Message{
		Type: ipv6.ICMPTypeEchoRequest,
		Code: 0,
		Body: &icmp.Echo{
			ID:   1,
			Seq:  1,
			Data: []byte("discover"),
		},
	}

	b, err := echo.Marshal(nil)
	if err != nil {
		return nil, err
	}

	if _, err := c.WriteTo(b, dst); err != nil {
		return nil, err
	}

	c.SetReadDeadline(time.Now().Add(3 * time.Second))

	var responders []string
	for {
		buf := make([]byte, 1500)
		n, peer, err := c.ReadFrom(buf)
		if err != nil {
			break // timeout or done
		}

		msg, err := icmp.ParseMessage(58, buf[:n]) // 58 = ICMPv6
		if err != nil {
			continue
		}

		if msg.Type == ipv6.ICMPTypeEchoReply {
			responders = append(responders, peer.String())
		}
	}

	return responders, nil
}
