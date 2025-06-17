package shared

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"os"
	"strings"

	"github.com/nextpki/certscan/internal/config"
)

var Config *config.Config

// Contains returns true if the string slice contains the given string.
func Contains(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

// GetPrimaryIP attempts to determine the primary outbound (non-loopback) IPv4 address of the agent.
// Returns "unknown" if no suitable address is found. This does not make an actual connection.
func GetPrimaryIP() string {
	ifaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range ifaces {
			if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
				continue
			}
			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}
			for _, addr := range addrs {
				var ip net.IP
				switch v := addr.(type) {
				case *net.IPNet:
					ip = v.IP
				case *net.IPAddr:
					ip = v.IP
				}
				if ip == nil || ip.IsLoopback() || ip.To4() == nil {
					continue
				}
				return ip.String()
			}
		}
	}
	// Fallback: try UDP dial method (does not actually connect)
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err == nil {
		defer conn.Close()
		if localAddr, ok := conn.LocalAddr().(*net.UDPAddr); ok {
			return localAddr.IP.String()
		}
	}
	return "unknown"
}

// GetMachineID returns a unique identifier for the agent machine.
// Tries config, then /etc/machine-id, then /var/lib/dbus/machine-id, then a hash of hostname+MAC.
func GetMachineID() string {
	if Config != nil && Config.MachineID != "" {
		return Config.MachineID
	}
	paths := []string{"/etc/machine-id", "/var/lib/dbus/machine-id"}
	for _, path := range paths {
		if data, err := os.ReadFile(path); err == nil {
			id := strings.TrimSpace(string(data))
			if id != "" {
				return id
			}
		}
	}
	// Fallback: hash of hostname and first non-loopback MAC
	hostname, _ := os.Hostname()
	mac := ""
	if ifaces, err := net.Interfaces(); err == nil {
		for _, iface := range ifaces {
			if iface.Flags&net.FlagLoopback == 0 && iface.Flags&net.FlagUp != 0 && len(iface.HardwareAddr) == 6 {
				mac = strings.ToLower(iface.HardwareAddr.String())
				break
			}
		}
	}
	seed := hostname + "-" + mac
	hash := sha256.Sum256([]byte(seed))
	return hex.EncodeToString(hash[:])[:32]
}
