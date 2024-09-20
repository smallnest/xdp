package xdp

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"

	"github.com/mdlayher/arp"
)

// LookupMacAddress returns the MAC address  with the given IP address.
func LookupMacAddress(ip string) (net.HardwareAddr, error) {
	targetIP, err := netip.ParseAddr(ip)
	if err != nil {
		return nil, err
	}

	iface, localIP, err := GetInterfaceForIP(ip)
	if err != nil {
		return nil, fmt.Errorf("failed to get interface for IP: %v", err)
	}

	if localIP == ip {
		return iface.HardwareAddr, nil
	}

	// check if the target IP is in the same subnet as the local IP
	sameSubnet, err := isSameSubnet(iface, ip)
	if err != nil {
		return nil, fmt.Errorf("failed to check subnet: %v", err)
	}

	var mac net.HardwareAddr

	if sameSubnet {
		// if in the same subnet, directly get the MAC address of the target IP
		conn, err := arp.Dial(iface)
		if err != nil {
			return nil, fmt.Errorf("failed to create ARP client: %v", err)
		}
		defer conn.Close()

		// send ARP request to get the corresponding MAC address
		mac, err = conn.Resolve(targetIP)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve IP: %v", err)
		}
	} else {
		// if not in the same subnet, get the MAC address of the gateway
		gatewayIP, err := getGatewayIP()
		if err != nil {
			return nil, fmt.Errorf("failed to get gateway IP: %v", err)
		}

		conn, err := arp.Dial(iface)
		if err != nil {
			return nil, fmt.Errorf("failed to create ARP client: %v", err)
		}
		defer conn.Close()

		// send ARP request to get the MAC address of the gateway
		mac, err = conn.Resolve(netip.MustParseAddr(gatewayIP.String()))
		if err != nil {
			return nil, fmt.Errorf("failed to resolve gateway IP: %v", err)
		}
	}

	return mac, nil
}

// GetInterfaceForIP geta the local network interface for the given remote IP.
func GetInterfaceForIP(ip string) (*net.Interface, string, error) {
	// use net.Dial to get the local IP address when connecting to the remote IP
	conn, err := net.Dial("udp", fmt.Sprintf("%s:80", ip))
	if err != nil {
		return nil, "", fmt.Errorf("failed to dial remote IP: %v", err)
	}
	defer conn.Close()

	// get the local IP address
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	localIP := localAddr.IP

	// find the network interface corresponding to the local IP
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, "", fmt.Errorf("failed to get interfaces: %v", err)
	}

	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, "", fmt.Errorf("failed to get addresses for interface %s: %v", iface.Name, err)
		}

		// check if any of the interface's IP addresses match the local IP
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip.Equal(localIP) {
				return &iface, localIP.String(), nil
			}
		}
	}

	return nil, localIP.String(), fmt.Errorf("no interface found for local IP: %s", localIP)
}

// isSameSubnet checks if the target IP is in the same subnet as the local IP
func isSameSubnet(iface *net.Interface, tIP string) (bool, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return false, fmt.Errorf("failed to get addresses for interface: %v", err)
	}

	targetIP := net.ParseIP(tIP)

	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok {
			if ipNet.Contains(targetIP) {
				return true, nil
			}
		}
	}

	return false, nil
}

// getGatewayIP reads the default gateway IP address from the Linux /proc/net/route file
func getGatewayIP() (net.IP, error) {
	file, err := os.Open("/proc/net/route")
	if err != nil {
		return nil, fmt.Errorf("failed to open /proc/net/route: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	// Skip the file header
	scanner.Scan()

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 11 {
			continue
		}

		// Check the Flags field, UG indicates a gateway
		flags := fields[3]
		if flags != "0003" { // If Flags is "0003", it indicates a gateway (both U and G flags are present)
			continue
		}

		// The hexadecimal IP address of the gateway is stored in the second field
		gatewayHex := fields[2]

		// Convert the hexadecimal gateway address to dotted decimal IP format
		gatewayIP := parseHexIP(gatewayHex)
		if gatewayIP == nil {
			return nil, errors.New("failed to parse gateway IP")
		}

		return gatewayIP, nil
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to scan /proc/net/route: %v", err)
	}

	return nil, errors.New("default gateway not found")
}

// parseHexIP: Convert a hexadecimal string to a net.IP address
func parseHexIP(hexStr string) net.IP {
	// The gateway address is a reversed hexadecimal string, so it needs to be parsed in reverse
	var ipBytes [4]byte
	_, err := fmt.Sscanf(hexStr, "%02X%02X%02X%02X", &ipBytes[3], &ipBytes[2], &ipBytes[1], &ipBytes[0])
	if err != nil {
		return nil
	}
	return net.IPv4(ipBytes[0], ipBytes[1], ipBytes[2], ipBytes[3])
}
