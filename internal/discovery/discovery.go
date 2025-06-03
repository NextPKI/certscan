package discovery

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/ultrapki/certscan/internal/shared"
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
// Returns a list of IPv6 addresses or an error.
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
			ip, _, err := net.ParseCIDR(addr.String())
			if err != nil || ip == nil || ip.To16() == nil || ip.To4() != nil {
				continue // skip non-IPv6
			}
			ifaceResponders, err := discoverIPv6OnInterface(iface.Name)
			if err == nil {
				for _, resp := range ifaceResponders {
					if IsExcluded(resp, excludeList) {
						continue
					}
					responders = append(responders, resp)
				}
			}
		}
	}
	return responders, nil
}

// discoverIPv6OnInterface sends an ICMPv6 multicast echo to ff02::1 on the given interface and returns responding IPs.
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
		return nil, err
	}

	if _, err := conn.WriteTo(msgBytes, dst); err != nil {
		return nil, err
	}

	conn.SetReadDeadline(time.Now().Add(time.Duration(shared.Config.ICMPTimeoutMs) * time.Millisecond))

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
