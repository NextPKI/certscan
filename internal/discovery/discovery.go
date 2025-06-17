package discovery

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/nextpki/certscan/internal/shared"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"
)

// incIP increments an IP address (IPv4 or IPv6) by one.
func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] != 0 {
			break
		}
	}
}

// ExpandCIDR expands an IPv4 CIDR to all contained IPs as strings, excluding the broadcast address.
func ExpandCIDR(cidr string) ([]string, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	if ipnet.IP.To4() == nil {
		return nil, nil // Only expand IPv4
	}
	var ips []string
	// Calculate broadcast IP
	broadcast := make(net.IP, len(ipnet.IP.To4()))
	for i := 0; i < len(ipnet.IP.To4()); i++ {
		broadcast[i] = ipnet.IP[i] | ^ipnet.Mask[i]
	}
	broadcastStr := broadcast.String()
	for ip := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
		ipCopy := net.ParseIP(ip.String())
		if ipCopy != nil && ipCopy.String() != broadcastStr {
			ips = append(ips, ipCopy.String())
		}
	}
	return ips, nil
}

// DiscoverIPv4Neighbors returns all IPv4 addresses on all non-loopback interfaces, excluding broadcast addresses.
func DiscoverIPv4Neighbors() ([]string, error) {
	excludeList := shared.Config.ExcludeList
	var discovered []string
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range interfaces {
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			ip, ipnet, err := net.ParseCIDR(addr.String())
			if err != nil || ip.To4() == nil {
				continue
			}
			if ip.IsLoopback() || ipnet.IP.IsLoopback() {
				continue
			}
			broadcast := make(net.IP, len(ipnet.IP.To4()))
			for i := 0; i < len(ipnet.IP.To4()); i++ {
				broadcast[i] = ipnet.IP[i] | ^ipnet.Mask[i]
			}
			broadcastStr := broadcast.String()
			for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
				ipCopy := net.ParseIP(ip.String())
				ipStr := ipCopy.String()
				if ipStr == broadcastStr {
					continue
				}
				if IsExcluded(ipStr, excludeList) {
					continue
				}
				discovered = append(discovered, ipStr)
			}
		}
	}
	return discovered, nil
}

func IsExcluded(host string, excludeList []string) bool {
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

// DiscoverIPv6Neighbors scans all interfaces and returns all responding IPv6 neighbors.
// Optionally, it performs a ping sweep and NDP sweep in the local /64 subnet if enabled in the config.
func DiscoverIPv6Neighbors() ([]string, error) {
	var responders []string
	excludeList := shared.Config.ExcludeList
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range interfaces {
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			ip, ipnet, err := net.ParseCIDR(addr.String())
			if err != nil || ip == nil || ip.To16() == nil || ip.To4() != nil {
				continue // skip non-IPv6
			}
			// ICMPv6 Multicast Echo (as before)
			ifaceResponders, err := discoverIPv6OnInterface(iface.Name)
			if err == nil {
				for _, resp := range ifaceResponders {
					if IsExcluded(resp, excludeList) {
						continue
					}
					responders = append(responders, resp)
				}
			}
			// Optional: ICMPv6 Echo Sweep in the local /64
			if shared.Config.EnableIPv6PingSweep && ipnet != nil {
				ones, bits := ipnet.Mask.Size()
				if ones == 64 && bits == 128 {
					for sweepIP := ip.Mask(ipnet.Mask); ipnet.Contains(sweepIP); incIP(sweepIP) {
						if sweepIP.Equal(ip) {
							continue // skip own address
						}
						resp, err := sendICMPv6Echo(sweepIP, iface.Name)
						if err == nil && resp != "" && !IsExcluded(resp, excludeList) {
							responders = append(responders, resp)
						}
					}
				}
			}
			// Optional: NDP Neighbor Solicitation Sweep in the local /64
			if shared.Config.EnableIPv6NDPSweep && ipnet != nil {
				ones, bits := ipnet.Mask.Size()
				if ones == 64 && bits == 128 {
					for sweepIP := ip.Mask(ipnet.Mask); ipnet.Contains(sweepIP); incIP(sweepIP) {
						if sweepIP.Equal(ip) {
							continue
						}
						resp, err := sendNDPSolicitation(sweepIP, iface.Name)
						if err == nil && resp != "" && !IsExcluded(resp, excludeList) {
							responders = append(responders, resp)
						}
					}
				}
			}
		}
	}
	return responders, nil
}

// sendICMPv6Echo sends an ICMPv6 Echo Request to a target address and returns the response IP (or empty string).
func sendICMPv6Echo(dstIP net.IP, ifaceName string) (string, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return "", err
	}
	conn, err := icmp.ListenPacket("udp6", fmt.Sprintf("%%%s", iface.Name))
	if err != nil {
		return "", err
	}
	defer conn.Close()
	dst := &net.UDPAddr{IP: dstIP, Zone: iface.Name}
	echo := icmp.Message{
		Type: ipv6.ICMPTypeEchoRequest,
		Code: 0,
		Body: &icmp.Echo{ID: os.Getpid() & 0xffff, Seq: 1, Data: []byte("certscan")},
	}
	msgBytes, err := echo.Marshal(nil)
	if err != nil {
		return "", err
	}
	if _, err := conn.WriteTo(msgBytes, dst); err != nil {
		return "", err
	}
	conn.SetReadDeadline(time.Now().Add(time.Duration(shared.Config.ICMPTimeoutMs) * time.Millisecond))
	buf := make([]byte, 1500)
	n, peer, err := conn.ReadFrom(buf)
	if err != nil {
		return "", err
	}
	msg, err := icmp.ParseMessage(58, buf[:n])
	if err != nil {
		return "", err
	}
	if msg.Type == ipv6.ICMPTypeEchoReply {
		return peer.(*net.UDPAddr).IP.String(), nil
	}
	return "", nil
}

// sendNDPSolicitation sends a Neighbor Solicitation to a target address and returns the response IP (or empty string).
func sendNDPSolicitation(dstIP net.IP, ifaceName string) (string, error) {
	// Not implemented yet because it would require this tool to run as root (raw sockets)
	return "", nil
}

// discoverIPv6OnInterface sends an ICMPv6 Multicast Echo Request (ff02::1) on the given interface
// and returns all responding neighbors as a list of IPs.
func discoverIPv6OnInterface(ifaceName string) ([]string, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, err
	}
	conn, err := icmp.ListenPacket("udp6", fmt.Sprintf("%%%s", iface.Name))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	dst := &net.UDPAddr{IP: net.ParseIP("ff02::1"), Zone: iface.Name}
	echo := icmp.Message{
		Type: ipv6.ICMPTypeEchoRequest,
		Code: 0,
		Body: &icmp.Echo{ID: os.Getpid() & 0xffff, Seq: 1, Data: []byte("certscan")},
	}
	msgBytes, err := echo.Marshal(nil)
	if err != nil {
		return nil, err
	}
	if _, err := conn.WriteTo(msgBytes, dst); err != nil {
		return nil, err
	}
	var responders []string
	conn.SetReadDeadline(time.Now().Add(time.Duration(shared.Config.ICMPTimeoutMs) * time.Millisecond))
	buf := make([]byte, 1500)
	for {
		n, peer, err := conn.ReadFrom(buf)
		if err != nil {
			break // timeout or no more responses
		}
		msg, err := icmp.ParseMessage(58, buf[:n])
		if err == nil && msg.Type == ipv6.ICMPTypeEchoReply {
			ip := peer.(*net.UDPAddr).IP.String()
			responders = append(responders, ip)
		}
	}
	return responders, nil
}
